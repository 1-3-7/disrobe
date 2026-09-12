#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_range_loop,
    clippy::manual_memcpy
)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph, PostDominator};
use disrobe_core::rng::{SeededRng, seeded};
use disrobe_core::{AdjGraph, DiGraph, Dominators, immediate_post_dominators};
use rand::RngExt;

fn dominator_sets<G: DiGraph>(graph: &G) -> Vec<BTreeSet<u32>> {
    let count: usize = graph.node_count();
    let entry: u32 = graph.entry();
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); count];
    for from in 0..count {
        graph.for_each_successor(from as u32, &mut |target: u32| {
            if (target as usize) < count {
                preds[target as usize].push(from as u32);
            }
        });
    }
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

fn naive_dominator_set(entry: u32, target: u32, successors: &[Vec<u32>]) -> BTreeSet<u32> {
    let count: usize = successors.len();
    let mut doms: BTreeSet<u32> = BTreeSet::new();
    for candidate in 0..count as u32 {
        if candidate == target || !reaches_avoiding(entry, target, candidate, successors) {
            doms.insert(candidate);
        }
    }
    doms
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

#[derive(Debug, Clone)]
struct Shape {
    successors: Vec<Vec<u32>>,
    exits: Vec<bool>,
}

impl Shape {
    fn graph(&self) -> FlowGraph<u32> {
        FlowGraph::build(
            0..self.successors.len() as u32,
            0,
            |node: u32, emit: &mut dyn FnMut(Flow<u32>)| {
                for &target in &self.successors[node as usize] {
                    emit(Flow::To(target));
                }
                if self.exits[node as usize] {
                    emit(Flow::Exit);
                }
            },
        )
        .expect("shape builds")
    }

    fn reachable(&self) -> Vec<bool> {
        let mut seen: Vec<bool> = vec![false; self.successors.len()];
        let mut stack: Vec<u32> = vec![0];
        seen[0] = true;
        while let Some(node) = stack.pop() {
            for &target in &self.successors[node as usize] {
                if !seen[target as usize] {
                    seen[target as usize] = true;
                    stack.push(target);
                }
            }
        }
        seen
    }

    fn adjacency(&self) -> AdjGraph {
        AdjGraph::new(0, self.successors.clone())
    }
}

struct ShapeGraph<'a> {
    shape: &'a Shape,
}

impl DiGraph for ShapeGraph<'_> {
    fn node_count(&self) -> usize {
        self.shape.successors.len()
    }

    fn entry(&self) -> u32 {
        0
    }

    fn for_each_successor(&self, node: u32, visit: &mut dyn FnMut(u32)) {
        for &target in &self.shape.successors[node as usize] {
            visit(target);
        }
    }
}

fn generated_shapes(count: usize) -> Vec<Shape> {
    let mut rng: SeededRng = seeded(0x5EED_D0C5);
    let mut shapes: Vec<Shape> = Vec::with_capacity(count + HAND_SHAPES.len());
    for spec in HAND_SHAPES {
        shapes.push(Shape {
            successors: spec
                .0
                .iter()
                .map(|row: &&[u32]| (*row).to_vec())
                .collect::<Vec<Vec<u32>>>(),
            exits: spec.1.to_vec(),
        });
    }
    for index in 0..count {
        let nodes: usize = 1 + (rng.random::<u32>() % 14) as usize;
        let irreducible: bool = index % 2 == 0;
        let mut successors: Vec<Vec<u32>> = vec![Vec::new(); nodes];
        for node in 0..nodes {
            let fanout: usize = (rng.random::<u32>() % 4) as usize;
            for _ in 0..fanout {
                let target: u32 = if irreducible {
                    rng.random::<u32>() % nodes as u32
                } else {
                    let span: u32 = (nodes - node) as u32;
                    node as u32 + (rng.random::<u32>() % span.max(1))
                };
                if (target as usize) < nodes {
                    successors[node].push(target);
                }
            }
            if rng.random::<u32>() % 6 == 0 {
                successors[node].push(node as u32);
            }
            if rng.random::<u32>() % 5 == 0 && !successors[node].is_empty() {
                let repeat: u32 = successors[node][0];
                successors[node].push(repeat);
            }
        }
        let exits: Vec<bool> = (0..nodes)
            .map(|node: usize| successors[node].is_empty() || rng.random::<u32>() % 4 == 0)
            .collect();
        shapes.push(Shape { successors, exits });
    }
    shapes
}

type HandShape = (&'static [&'static [u32]], &'static [bool]);

const HAND_SHAPES: &[HandShape] = &[
    (&[&[]], &[true]),
    (&[&[0]], &[false]),
    (&[&[1], &[0]], &[false, false]),
    (&[&[1, 2], &[], &[]], &[false, true, true]),
    (&[&[1, 2], &[2], &[1, 3], &[]], &[false, false, false, true]),
    (&[&[1], &[], &[1]], &[false, true, false]),
    (&[&[1], &[0, 2], &[]], &[false, false, true]),
    (
        &[&[1, 1, 2, 2], &[3, 3], &[3], &[]],
        &[false, false, false, true],
    ),
    (&[&[1], &[2], &[3], &[1]], &[false, false, false, false]),
    (
        &[&[1, 2], &[3], &[3], &[4], &[3]],
        &[false, false, false, false, false],
    ),
];

fn dag_shapes(count: usize) -> Vec<Shape> {
    let mut rng: SeededRng = seeded(0x0DAD_0DAD);
    (0..count)
        .map(|_| {
            let nodes: usize = 1 + (rng.random::<u32>() % 12) as usize;
            let mut successors: Vec<Vec<u32>> = vec![Vec::new(); nodes];
            for node in 0..nodes {
                let fanout: usize = (rng.random::<u32>() % 3) as usize;
                for _ in 0..fanout {
                    let remaining: u32 = (nodes - node - 1) as u32;
                    if remaining == 0 {
                        continue;
                    }
                    let target: u32 = node as u32 + 1 + (rng.random::<u32>() % remaining);
                    successors[node].push(target);
                }
            }
            let exits: Vec<bool> = (0..nodes)
                .map(|node: usize| successors[node].is_empty())
                .collect();
            Shape { successors, exits }
        })
        .collect()
}

fn reference_dotnet_reverse_postorder(
    entry: usize,
    succs: &[Vec<usize>],
    total: usize,
) -> (Vec<usize>, Vec<usize>) {
    let mut visited: Vec<bool> = vec![false; total];
    let mut order: Vec<usize> = Vec::with_capacity(total);
    let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
    visited[entry] = true;
    while let Some(&mut (node, ref mut idx)) = stack.last_mut() {
        if *idx < succs[node].len() {
            let child: usize = succs[node][*idx];
            *idx += 1;
            if !visited[child] {
                visited[child] = true;
                stack.push((child, 0));
            }
        } else {
            order.push(node);
            stack.pop();
        }
    }
    let mut post_num: Vec<usize> = vec![usize::MAX; total];
    for (i, &b) in order.iter().enumerate() {
        post_num[b] = i;
    }
    order.reverse();
    (post_num, order)
}

fn reference_dotnet_intersect(
    mut a: usize,
    mut b: usize,
    idom: &[usize],
    post_num: &[usize],
) -> usize {
    let mut guard: usize = 0;
    while a != b {
        while post_num[a] < post_num[b] {
            a = idom[a];
            guard += 1;
            if guard > idom.len() * 4 {
                return a;
            }
        }
        while post_num[b] < post_num[a] {
            b = idom[b];
            guard += 1;
            if guard > idom.len() * 4 {
                return b;
            }
        }
        guard += 1;
        if guard > idom.len() * 4 {
            return a;
        }
    }
    a
}

fn reference_dotnet_ipdom(shape: &Shape) -> Vec<usize> {
    let count: usize = shape.successors.len();
    let virtual_exit: usize = count;
    let total: usize = count + 1;
    let mut rsuccs: Vec<Vec<usize>> = vec![Vec::new(); total];
    for bid in 0..count {
        if shape.exits[bid] {
            rsuccs[bid].push(virtual_exit);
        } else {
            rsuccs[bid].extend(shape.successors[bid].iter().map(|s: &u32| *s as usize));
        }
    }
    let mut rpreds: Vec<Vec<usize>> = vec![Vec::new(); total];
    for (n, succs) in rsuccs.iter().enumerate() {
        for &s in succs {
            rpreds[s].push(n);
        }
    }
    let (post_num, rpo): (Vec<usize>, Vec<usize>) =
        reference_dotnet_reverse_postorder(virtual_exit, &rpreds, total);
    let undefined: usize = usize::MAX;
    let mut ipdom: Vec<usize> = vec![undefined; total];
    ipdom[virtual_exit] = virtual_exit;
    let mut changed: bool = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == virtual_exit {
                continue;
            }
            let mut new_ipdom: usize = undefined;
            for &p in &rsuccs[b] {
                if ipdom[p] == undefined {
                    continue;
                }
                new_ipdom = if new_ipdom == undefined {
                    p
                } else {
                    reference_dotnet_intersect(p, new_ipdom, &ipdom, &post_num)
                };
            }
            if new_ipdom != undefined && ipdom[b] != new_ipdom {
                ipdom[b] = new_ipdom;
                changed = true;
            }
        }
    }
    ipdom.truncate(count);
    for d in &mut ipdom {
        if *d == virtual_exit {
            *d = usize::MAX;
        }
    }
    ipdom
}

fn reference_pseudo_c_idom(shape: &Shape) -> Vec<Option<usize>> {
    let count: usize = shape.successors.len();
    let graph: ShapeGraph<'_> = ShapeGraph { shape };
    let dom: Vec<BTreeSet<usize>> = dominator_sets(&graph)
        .into_iter()
        .map(|set: BTreeSet<u32>| set.into_iter().map(|id: u32| id as usize).collect())
        .collect();
    let mut idom: Vec<Option<usize>> = vec![None; count];
    for node in 1..count {
        let strict: Vec<usize> = dom[node]
            .iter()
            .copied()
            .filter(|d: &usize| *d != node)
            .collect();
        idom[node] = strict.iter().copied().find(|cand: &usize| {
            strict
                .iter()
                .all(|other: &usize| other == cand || dom[*cand].contains(other))
        });
    }
    idom
}

fn reference_pseudo_c_pdom(shape: &Shape) -> Vec<BTreeSet<usize>> {
    let count: usize = shape.successors.len();
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); count];
    for (from, targets) in shape.successors.iter().enumerate() {
        for &target in targets {
            if !preds[target as usize].contains(&(from as u32)) {
                preds[target as usize].push(from as u32);
            }
        }
    }
    let mut reverse: Vec<Vec<u32>> = vec![Vec::new(); count + 1];
    for node in 0..count {
        reverse[node].clone_from(&preds[node]);
    }
    for node in 0..count {
        if shape.exits[node] {
            reverse[count].push(node as u32);
        }
    }
    let graph: AdjGraph = AdjGraph::new(count as u32, reverse);
    let exit: u32 = count as u32;
    dominator_sets(&graph)[..count]
        .iter()
        .map(|set: &BTreeSet<u32>| {
            set.iter()
                .filter(|&&n: &&u32| n != exit)
                .map(|&n: &u32| n as usize)
                .collect()
        })
        .collect()
}

fn reference_chain_dominates(idom: &[Option<u32>], entry: u32, ancestor: u32, child: u32) -> bool {
    let mut current: Option<u32> = Some(child);
    let mut steps: usize = 0;
    while let Some(node) = current {
        if node == ancestor {
            return true;
        }
        if node == entry {
            return false;
        }
        match idom.get(node as usize).copied().flatten() {
            Some(parent) if parent == node => return false,
            Some(parent) => current = Some(parent),
            None => return false,
        }
        steps += 1;
        if steps > idom.len() {
            return false;
        }
    }
    false
}

fn reference_wasm_ipdom(shape: &Shape) -> BTreeMap<u32, Option<u32>> {
    let count: usize = shape.successors.len();
    let virtual_exit: u32 = count as u32;
    let raw: Vec<Option<u32>> =
        immediate_post_dominators(count, |from: u32, emit: &mut dyn FnMut(u32)| {
            for &target in &shape.successors[from as usize] {
                emit(target);
            }
            if shape.exits[from as usize] {
                emit(virtual_exit);
            }
        });
    raw.into_iter()
        .enumerate()
        .map(|(node, target): (usize, Option<u32>)| (node as u32, target))
        .collect()
}

fn reference_nir_natural_loop(shape: &Shape, header: u32, doms: &Dominators) -> BTreeSet<u32> {
    let count: usize = shape.successors.len();
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); count];
    for (from, targets) in shape.successors.iter().enumerate() {
        for &target in targets {
            if !preds[target as usize].contains(&(from as u32)) {
                preds[target as usize].push(from as u32);
            }
        }
    }
    let mut nodes: BTreeSet<u32> = BTreeSet::from([header]);
    let mut pending: Vec<u32> = preds[header as usize]
        .iter()
        .copied()
        .filter(|predecessor: &u32| doms.dominates(header, *predecessor))
        .collect();
    while let Some(node) = pending.pop() {
        if !nodes.insert(node) || node == header {
            continue;
        }
        for predecessor in &preds[node as usize] {
            if doms.dominates(header, *predecessor) && !nodes.contains(predecessor) {
                pending.push(*predecessor);
            }
        }
    }
    nodes
}

fn reference_reactor_dominates(shape: &Shape, dominator: usize, target: usize) -> bool {
    let live: Vec<bool> = shape.reachable();
    if !live[dominator] || !live[target] {
        return false;
    }
    if dominator == target {
        return true;
    }
    let count: usize = shape.successors.len();
    let mut visited: Vec<bool> = vec![false; count];
    let mut pending: Vec<usize> = vec![0];
    while let Some(index) = pending.pop() {
        if index == dominator || visited[index] {
            continue;
        }
        if index == target {
            return false;
        }
        visited[index] = true;
        pending.extend(shape.successors[index].iter().map(|s: &u32| *s as usize));
    }
    true
}

#[test]
fn the_shared_post_dominators_match_the_deleted_dotnet_engine() {
    for shape in generated_shapes(600) {
        let graph: FlowGraph<u32> = shape.graph();
        let reference: Vec<usize> = reference_dotnet_ipdom(&shape);
        for node in 0..shape.successors.len() {
            let actual: usize = match graph.immediate_post_dominator(node as u32) {
                PostDominator::Node(target) => target as usize,
                PostDominator::FunctionExit | PostDominator::Undefined => usize::MAX,
            };
            assert_eq!(
                actual, reference[node],
                "ipdom for block {node} in {:?} exits={:?}",
                shape.successors, shape.exits
            );
        }
    }
}

#[test]
fn the_shared_post_dominators_match_the_deleted_wasm_adapter() {
    for shape in generated_shapes(600) {
        let graph: FlowGraph<u32> = shape.graph();
        let reference: BTreeMap<u32, Option<u32>> = reference_wasm_ipdom(&shape);
        let exit: u32 = shape.successors.len() as u32;
        for node in 0..shape.successors.len() as u32 {
            let expected: PostDominator<u32> = match reference.get(&node).copied().flatten() {
                None => PostDominator::Undefined,
                Some(target) if target == exit => PostDominator::FunctionExit,
                Some(target) => PostDominator::Node(target),
            };
            assert_eq!(
                graph.immediate_post_dominator(node),
                expected,
                "ipdom for state {node} in {:?}",
                shape.successors
            );
        }
    }
}

fn every_live_predecessor_is_live(shape: &Shape, live: &[bool]) -> bool {
    shape
        .successors
        .iter()
        .enumerate()
        .all(|(from, targets): (usize, &Vec<u32>)| {
            live[from] || targets.iter().all(|target: &u32| !live[*target as usize])
        })
}

#[test]
fn the_shared_dominators_match_the_deleted_dominator_set_adapters_on_fully_reachable_graphs() {
    let mut compared: usize = 0;
    for shape in generated_shapes(600) {
        let live: Vec<bool> = shape.reachable();
        if !live.iter().all(|reached: &bool| *reached) {
            continue;
        }
        compared += 1;
        let graph: FlowGraph<u32> = shape.graph();
        let adjacency: AdjGraph = shape.adjacency();
        let reference: Vec<BTreeSet<u32>> = dominator_sets(&adjacency);
        for node in 0..shape.successors.len() as u32 {
            assert_eq!(
                graph.dominator_set(node),
                reference[node as usize],
                "dominator set for block {node} in {:?}",
                shape.successors
            );
        }
    }
    assert!(compared > 40, "only {compared} fully reachable graphs");
}

#[test]
fn where_the_deleted_dominator_set_fixpoint_disagrees_the_shared_answer_is_the_correct_one() {
    let mut divergences: usize = 0;
    for shape in generated_shapes(600) {
        let live: Vec<bool> = shape.reachable();
        let graph: FlowGraph<u32> = shape.graph();
        let adjacency: AdjGraph = shape.adjacency();
        let reference: Vec<BTreeSet<u32>> = dominator_sets(&adjacency);
        for node in 0..shape.successors.len() as u32 {
            let actual: BTreeSet<u32> = graph.dominator_set(node);
            if !live[node as usize] {
                assert!(
                    actual.is_empty(),
                    "unreachable block {node} must have no dominators"
                );
                continue;
            }
            let truth: BTreeSet<u32> = naive_dominator_set(0, node, &shape.successors)
                .into_iter()
                .filter(|candidate: &u32| live[*candidate as usize])
                .collect();
            assert_eq!(
                actual, truth,
                "dominator set for block {node} in {:?}",
                shape.successors
            );
            if reference[node as usize] != truth {
                divergences += 1;
                assert!(
                    !every_live_predecessor_is_live(&shape, &live),
                    "the fixpoint only diverged where a live block had an unreachable predecessor"
                );
            }
        }
    }
    assert!(
        divergences > 0,
        "the divergence this test records must be observable"
    );
}

#[test]
fn the_shared_immediate_dominators_match_the_deleted_pseudo_c_derivation_on_fully_reachable_graphs()
{
    let mut compared: usize = 0;
    for shape in generated_shapes(600) {
        let live: Vec<bool> = shape.reachable();
        if !live.iter().all(|reached: &bool| *reached) {
            continue;
        }
        compared += 1;
        let graph: FlowGraph<u32> = shape.graph();
        let reference: Vec<Option<usize>> = reference_pseudo_c_idom(&shape);
        for node in 0..shape.successors.len() {
            assert_eq!(
                graph
                    .immediate_dominator(node as u32)
                    .map(|d: u32| d as usize),
                reference[node],
                "idom for block {node} in {:?}",
                shape.successors
            );
        }
    }
    assert!(compared > 40, "only {compared} fully reachable graphs");
}

#[test]
fn the_shared_post_dominator_chain_matches_the_deleted_pseudo_c_sets_on_blocks_that_reach_an_exit()
{
    for shape in generated_shapes(600) {
        let graph: FlowGraph<u32> = shape.graph();
        let reference: Vec<BTreeSet<usize>> = reference_pseudo_c_pdom(&shape);
        for node in 0..shape.successors.len() {
            if !graph.exit_post_dominates(node as u32) {
                continue;
            }
            let mut actual: BTreeSet<usize> = BTreeSet::from([node]);
            let mut current: u32 = node as u32;
            while let PostDominator::Node(next) = graph.immediate_post_dominator(current) {
                if !actual.insert(next as usize) {
                    break;
                }
                current = next;
            }
            assert_eq!(
                actual, reference[node],
                "post-dominator set for block {node} in {:?} exits={:?}",
                shape.successors, shape.exits
            );
        }
    }
}

#[test]
fn the_shared_dominates_matches_the_deleted_chain_walks_except_on_unreachable_self_queries() {
    for shape in generated_shapes(600) {
        let graph: FlowGraph<u32> = shape.graph();
        let live: Vec<bool> = shape.reachable();
        let adjacency: AdjGraph = shape.adjacency();
        let doms: Dominators = Dominators::compute(&adjacency);
        let count: u32 = shape.successors.len() as u32;
        let idom: Vec<Option<u32>> = (0..count)
            .map(|node: u32| doms.immediate_dominator(node))
            .collect();
        for child in 0..count {
            for ancestor in 0..count {
                let reference: bool = reference_chain_dominates(&idom, 0, ancestor, child);
                let actual: bool = graph.dominates(ancestor, child);
                if live[child as usize] {
                    assert_eq!(
                        actual, reference,
                        "dominates({ancestor},{child}) in {:?}",
                        shape.successors
                    );
                } else {
                    assert!(
                        !actual,
                        "unreachable block {child} must not be dominated by {ancestor}"
                    );
                    assert!(
                        ancestor == child || !reference,
                        "the deleted walks only differed on the self query"
                    );
                }
            }
        }
    }
}

#[test]
fn the_shared_loop_body_matches_the_deleted_nir_predecessor_walk() {
    for shape in generated_shapes(600) {
        let graph: FlowGraph<u32> = shape.graph();
        let adjacency: AdjGraph = shape.adjacency();
        let doms: Dominators = Dominators::compute(&adjacency);
        let live: Vec<bool> = shape.reachable();
        for header in 0..shape.successors.len() as u32 {
            if !live[header as usize] {
                continue;
            }
            let latches: Vec<u32> = graph
                .predecessors(header)
                .filter(|predecessor: &u32| graph.dominates(header, *predecessor))
                .collect();
            if latches.is_empty() {
                continue;
            }
            assert_eq!(
                graph.natural_loop_body(header, &latches),
                reference_nir_natural_loop(&shape, header, &doms),
                "loop body for header {header} in {:?}",
                shape.successors
            );
        }
    }
}

#[test]
fn the_shared_dominates_matches_the_deleted_reactor_search_on_acyclic_graphs() {
    for shape in dag_shapes(400) {
        let graph: FlowGraph<u32> = shape.graph();
        for target in 0..shape.successors.len() {
            for dominator in 0..shape.successors.len() {
                assert_eq!(
                    graph.dominates(dominator as u32, target as u32),
                    reference_reactor_dominates(&shape, dominator, target),
                    "dominates({dominator},{target}) in {:?}",
                    shape.successors
                );
            }
        }
    }
}

#[test]
fn the_shared_back_edges_match_the_deleted_dominator_set_scan_on_fully_reachable_graphs() {
    let mut compared: usize = 0;
    for shape in generated_shapes(600) {
        let live: Vec<bool> = shape.reachable();
        if !live.iter().all(|reached: &bool| *reached) {
            continue;
        }
        compared += 1;
        let graph: FlowGraph<u32> = shape.graph();
        let adjacency: AdjGraph = shape.adjacency();
        let reference_sets: Vec<BTreeSet<u32>> = dominator_sets(&adjacency);
        let mut reference: Vec<(u32, u32)> = Vec::new();
        for (from, targets) in shape.successors.iter().enumerate() {
            let mut seen: Vec<u32> = Vec::new();
            for &target in targets {
                if seen.contains(&target) {
                    continue;
                }
                seen.push(target);
                if reference_sets[from].contains(&target) {
                    reference.push((from as u32, target));
                }
            }
        }
        assert_eq!(
            graph.back_edges(),
            reference,
            "back edges in {:?}",
            shape.successors
        );
    }
    assert!(compared > 40, "only {compared} fully reachable graphs");
}
