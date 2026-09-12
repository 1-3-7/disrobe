#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_similarity::{
    BasicBlock, ControlFlowFingerprint, ControlFlowGraph, INSTRUCTION_CATEGORY_COUNT,
    InstructionCategory, InstructionMix, MINIMUM_DISTINGUISHING_BLOCKS,
};

fn block<const N: usize, const M: usize>(
    successors: [usize; N],
    categories: [InstructionCategory; M],
) -> BasicBlock {
    BasicBlock::new(successors, categories)
}

fn graph(entry: usize, blocks: Vec<BasicBlock>) -> ControlFlowGraph {
    ControlFlowGraph::new(entry, blocks).expect("the fixture graph is well formed")
}

const fn body(seed: usize) -> [InstructionCategory; 2] {
    [
        InstructionCategory::Move,
        InstructionCategory::ALL[seed % INSTRUCTION_CATEGORY_COUNT],
    ]
}

fn loop_with_early_exit() -> ControlFlowGraph {
    graph(
        0,
        vec![
            block([1], body(0)),
            block([2, 4], body(1)),
            block([3], body(2)),
            block([1, 4], body(3)),
            block([], body(4)),
        ],
    )
}

fn loop_with_early_exit_relabelled() -> ControlFlowGraph {
    graph(
        3,
        vec![
            block([4, 1], body(1)),
            block([], body(4)),
            block([0, 1], body(3)),
            block([0], body(0)),
            block([2], body(2)),
        ],
    )
}

#[test]
fn the_same_shape_listed_in_a_different_block_order_keeps_its_fingerprint() {
    let canonical: ControlFlowGraph = loop_with_early_exit();
    let relabelled: ControlFlowGraph = loop_with_early_exit_relabelled();

    assert_ne!(
        canonical.blocks(),
        relabelled.blocks(),
        "the two fixtures must differ in listing order, otherwise this proves nothing"
    );
    assert_eq!(canonical.block_count(), relabelled.block_count());
    assert_eq!(canonical.edge_count(), relabelled.edge_count());
    assert_eq!(
        canonical.fingerprint(),
        relabelled.fingerprint(),
        "the block ordering must come from the graph, never from the order blocks were listed in"
    );
    assert_eq!(canonical.instruction_mix(), relabelled.instruction_mix());
    assert_eq!(canonical.structural_key(), relabelled.structural_key());
}

#[test]
fn reversing_the_successor_list_of_every_block_keeps_the_fingerprint() {
    let forward: ControlFlowGraph = loop_with_early_exit();
    let reversed: ControlFlowGraph = graph(
        forward.entry(),
        forward
            .blocks()
            .iter()
            .map(|source: &BasicBlock| {
                BasicBlock::new(
                    source.successors().iter().rev().copied(),
                    source.categories().iter().copied(),
                )
            })
            .collect(),
    );

    assert_eq!(forward.fingerprint(), reversed.fingerprint());
}

#[test]
fn genuinely_different_shapes_produce_different_fingerprints() {
    let shapes: Vec<(&str, ControlFlowGraph)> = vec![
        (
            "chain",
            graph(
                0,
                vec![block([1], body(0)), block([2], body(1)), block([], body(2))],
            ),
        ),
        (
            "if then",
            graph(
                0,
                vec![
                    block([1, 2], body(0)),
                    block([2], body(1)),
                    block([], body(2)),
                ],
            ),
        ),
        (
            "self loop",
            graph(
                0,
                vec![
                    block([1], body(0)),
                    block([1, 2], body(1)),
                    block([], body(2)),
                ],
            ),
        ),
        (
            "diamond",
            graph(
                0,
                vec![
                    block([1, 2], body(0)),
                    block([3], body(1)),
                    block([3], body(2)),
                    block([], body(3)),
                ],
            ),
        ),
        (
            "if then else with an early return",
            graph(
                0,
                vec![
                    block([1, 2], body(0)),
                    block([3], body(1)),
                    block([], body(2)),
                    block([], body(3)),
                ],
            ),
        ),
        ("loop with an early exit", loop_with_early_exit()),
        (
            "nested loop",
            graph(
                0,
                vec![
                    block([1], body(0)),
                    block([2, 5], body(1)),
                    block([3], body(2)),
                    block([2, 4], body(3)),
                    block([1], body(4)),
                    block([], body(5)),
                ],
            ),
        ),
        (
            "four arm switch",
            graph(
                0,
                vec![
                    block([1, 2, 3, 4], body(0)),
                    block([5], body(1)),
                    block([5], body(2)),
                    block([5], body(3)),
                    block([5], body(4)),
                    block([], body(5)),
                ],
            ),
        ),
    ];

    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for (label, shape) in &shapes {
        let fingerprint: ControlFlowFingerprint = shape.fingerprint();
        assert!(
            seen.insert(fingerprint.value()),
            "{label} collided with an earlier shape at {:#018x}",
            fingerprint.value()
        );
    }
    assert_eq!(seen.len(), shapes.len());
}

#[test]
fn an_unreachable_block_changes_the_fingerprint() {
    let reachable: ControlFlowGraph = graph(
        0,
        vec![
            block([1, 2], body(0)),
            block([2], body(1)),
            block([], body(2)),
        ],
    );
    let with_orphan: ControlFlowGraph = graph(
        0,
        vec![
            block([1, 2], body(0)),
            block([2], body(1)),
            block([], body(2)),
            block([2], body(3)),
        ],
    );

    assert_ne!(reachable.fingerprint(), with_orphan.fingerprint());
}

#[test]
fn a_graph_naming_a_block_that_does_not_exist_is_refused() {
    assert_eq!(
        ControlFlowGraph::new(0, vec![block([7], body(0)), block([], body(1))]),
        None
    );
    assert_eq!(ControlFlowGraph::new(2, vec![block([], body(0))]), None);
    assert_eq!(ControlFlowGraph::new(0, Vec::new()), None);
}

#[test]
fn the_block_floor_is_the_smallest_graph_that_can_branch() {
    assert_eq!(MINIMUM_DISTINGUISHING_BLOCKS, 3);
    let two: ControlFlowGraph = graph(0, vec![block([1], body(0)), block([], body(1))]);
    let three: ControlFlowGraph = graph(
        0,
        vec![
            block([1, 2], body(0)),
            block([2], body(1)),
            block([], body(2)),
        ],
    );

    assert_eq!(two.structural_key(), None);
    assert!(three.structural_key().is_some());
}

#[test]
fn the_instruction_mix_counts_every_category_across_every_block() {
    let shape: ControlFlowGraph = graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([2], [InstructionCategory::Load, InstructionCategory::Load]),
            block([], [InstructionCategory::Return]),
        ],
    );

    let mix: InstructionMix = shape.instruction_mix();
    assert_eq!(mix.count(InstructionCategory::Load), 2);
    assert_eq!(mix.count(InstructionCategory::Compare), 1);
    assert_eq!(mix.count(InstructionCategory::Branch), 1);
    assert_eq!(mix.count(InstructionCategory::Return), 1);
    assert_eq!(mix.count(InstructionCategory::Vector), 0);
    assert_eq!(mix.total(), 5);
    assert!(!mix.is_empty());
    assert!(InstructionMix::default().is_empty());
}

#[test]
fn every_category_occupies_its_own_position() {
    assert_eq!(InstructionCategory::ALL.len(), INSTRUCTION_CATEGORY_COUNT);
    let positions: BTreeSet<usize> = InstructionCategory::ALL
        .iter()
        .map(|category: &InstructionCategory| category.position())
        .collect();
    assert_eq!(positions.len(), INSTRUCTION_CATEGORY_COUNT);
    for category in InstructionCategory::ALL {
        let mix: InstructionMix = InstructionMix::tally([category, category]);
        assert_eq!(mix.count(category), 2);
        assert_eq!(mix.total(), 2);
    }
}
