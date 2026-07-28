#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_similarity::{
    BasicBlock, ControlFlowGraph, DataReference, FunctionFeatures, FunctionId, InstructionCategory,
    InstructionMix, MatchReport, MatchStage, UnmatchedCause, Verdict, match_functions,
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

fn loop_with_exit(body: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block([1], [InstructionCategory::Stack, InstructionCategory::Move]),
            block(
                [2, 4],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([3], [body, body]),
            block(
                [1, 4],
                [InstructionCategory::Arithmetic, InstructionCategory::Branch],
            ),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn diamond() -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([3], [InstructionCategory::Load]),
            block([3], [InstructionCategory::Store]),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn shaped(id: u64, structure: ControlFlowGraph) -> FunctionFeatures {
    FunctionFeatures::with_structure(FunctionId(id), [], structure)
}

fn candidates<const N: usize>(ids: [u64; N]) -> BTreeSet<FunctionId> {
    ids.into_iter().map(FunctionId).collect()
}

#[test]
fn a_third_function_carrying_the_same_shape_refuses_the_match() {
    let left: Vec<FunctionFeatures> = vec![
        shaped(0x1000, loop_with_exit(InstructionCategory::Arithmetic)),
        shaped(0x1100, loop_with_exit(InstructionCategory::Arithmetic)),
        shaped(0x1200, loop_with_exit(InstructionCategory::Arithmetic)),
    ];
    let right: Vec<FunctionFeatures> = vec![shaped(
        0x2000,
        loop_with_exit(InstructionCategory::Arithmetic),
    )];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.structural_count(), 0);
    assert!(report.matched_pairs().is_empty());
    for subject in [0x1000_u64, 0x1100, 0x1200] {
        assert_eq!(
            report.left_verdict(FunctionId(subject)),
            Some(&Verdict::Ambiguous {
                candidates: candidates([0x2000]),
                own_side: 3,
                other_side: 1,
            }),
            "a shape held by three functions names its candidates instead of guessing one"
        );
    }
    assert_eq!(
        report.right_verdict(FunctionId(0x2000)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x1000, 0x1100, 0x1200]),
            own_side: 1,
            other_side: 3,
        })
    );
}

#[test]
fn three_functions_sharing_a_shape_on_the_other_side_also_refuse_the_match() {
    let left: Vec<FunctionFeatures> = vec![shaped(
        0x1000,
        loop_with_exit(InstructionCategory::Arithmetic),
    )];
    let right: Vec<FunctionFeatures> = vec![
        shaped(0x2000, loop_with_exit(InstructionCategory::Arithmetic)),
        shaped(0x2100, loop_with_exit(InstructionCategory::Arithmetic)),
        shaped(0x2200, loop_with_exit(InstructionCategory::Arithmetic)),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.structural_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x2000, 0x2100, 0x2200]),
            own_side: 1,
            other_side: 3,
        })
    );
}

#[test]
fn a_shape_unique_on_both_sides_matches_and_carries_its_own_evidence() {
    let shape: ControlFlowGraph = loop_with_exit(InstructionCategory::Arithmetic);
    let left: Vec<FunctionFeatures> =
        vec![shaped(0x1000, shape.clone()), shaped(0x1100, diamond())];
    let right: Vec<FunctionFeatures> = vec![shaped(0x2000, shape.clone())];

    let report: MatchReport = match_functions(&left, &right);

    assert!(report.exact_pairs().is_empty());
    assert_eq!(
        report.structural_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Structural {
            counterpart: FunctionId(0x2000),
            fingerprint: shape.fingerprint(),
            instruction_mix: shape.instruction_mix(),
        })
    );
    assert_eq!(
        report
            .left_verdict(FunctionId(0x1000))
            .and_then(Verdict::stage),
        Some(MatchStage::ControlFlow)
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        }),
        "a shape with no counterpart keeps the verdict the reference stage left"
    );
}

#[test]
fn the_same_shape_with_a_different_instruction_mix_does_not_match() {
    let arithmetic: ControlFlowGraph = loop_with_exit(InstructionCategory::Arithmetic);
    let calling: ControlFlowGraph = loop_with_exit(InstructionCategory::Call);
    assert_eq!(
        arithmetic.fingerprint(),
        calling.fingerprint(),
        "the two fixtures must share a shape, otherwise this proves nothing about the corroborator"
    );
    assert_ne!(arithmetic.instruction_mix(), calling.instruction_mix());

    let left: Vec<FunctionFeatures> = vec![shaped(0x1000, arithmetic)];
    let right: Vec<FunctionFeatures> = vec![shaped(0x2000, calling)];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.structural_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        }),
        "an identical control-flow skeleton over different computation is a collision, not a match"
    );
}

#[test]
fn different_shapes_with_the_same_instruction_mix_do_not_match() {
    let categories: [InstructionCategory; 4] = [
        InstructionCategory::Compare,
        InstructionCategory::Branch,
        InstructionCategory::Load,
        InstructionCategory::Return,
    ];
    let chain: ControlFlowGraph = graph(
        0,
        vec![
            block([1], [categories[0]]),
            block([2], [categories[1]]),
            block([], [categories[2], categories[3]]),
        ],
    );
    let branching: ControlFlowGraph = graph(
        0,
        vec![
            block([1, 2], [categories[0]]),
            block([2], [categories[1]]),
            block([], [categories[2], categories[3]]),
        ],
    );
    assert_eq!(chain.instruction_mix(), branching.instruction_mix());
    assert_ne!(chain.fingerprint(), branching.fingerprint());

    let report: MatchReport =
        match_functions(&[shaped(0x1000, chain)], &[shaped(0x2000, branching)]);

    assert_eq!(report.structural_count(), 0);
}

#[test]
fn a_graph_below_the_block_floor_is_never_keyed() {
    let straight_line: ControlFlowGraph = graph(
        0,
        vec![
            block([1], [InstructionCategory::Move]),
            block([], [InstructionCategory::Return]),
        ],
    );
    assert_eq!(straight_line.structural_key(), None);

    let report: MatchReport = match_functions(
        &[shaped(0x1000, straight_line.clone())],
        &[shaped(0x2000, straight_line)],
    );

    assert_eq!(report.structural_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
}

#[test]
fn a_graph_without_a_single_instruction_category_is_never_keyed() {
    let bare: ControlFlowGraph = graph(0, vec![block([1, 2], []), block([2], []), block([], [])]);
    assert_eq!(bare.instruction_mix(), InstructionMix::default());
    assert_eq!(
        bare.structural_key(),
        None,
        "with no instruction mix there is nothing to corroborate the shape"
    );

    let report: MatchReport =
        match_functions(&[shaped(0x1000, bare.clone())], &[shaped(0x2000, bare)]);

    assert_eq!(report.structural_count(), 0);
}

#[test]
fn a_function_carrying_no_structure_stays_with_its_reference_verdict() {
    let left: Vec<FunctionFeatures> = vec![
        FunctionFeatures::new(
            FunctionId(0x1000),
            [DataReference::string_literal("left only")],
        ),
        shaped(0x1100, loop_with_exit(InstructionCategory::Arithmetic)),
    ];
    let right: Vec<FunctionFeatures> = vec![shaped(
        0x2000,
        loop_with_exit(InstructionCategory::Arithmetic),
    )];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        })
    );
    assert_eq!(
        report.structural_pairs(),
        vec![(FunctionId(0x1100), FunctionId(0x2000))]
    );
}
