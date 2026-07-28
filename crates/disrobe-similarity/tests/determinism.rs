#![allow(clippy::expect_used, clippy::panic)]

use disrobe_similarity::{
    BasicBlock, ControlFlowGraph, DataReference, FunctionFeatures, FunctionId, FunctionVerdict,
    InstructionCategory, MatchReport, Verdict, match_functions,
};

fn features<const N: usize>(id: u64, references: [DataReference; N]) -> FunctionFeatures {
    FunctionFeatures::new(FunctionId(id), references)
}

fn block<const N: usize, const M: usize>(
    successors: [usize; N],
    categories: [InstructionCategory; M],
) -> BasicBlock {
    BasicBlock::new(successors, categories)
}

fn graph(entry: usize, blocks: Vec<BasicBlock>) -> ControlFlowGraph {
    ControlFlowGraph::new(entry, blocks).expect("the fixture graph is well formed")
}

fn diamond(arm: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([3], [arm]),
            block([3], [InstructionCategory::Store]),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn triangle() -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([2], [InstructionCategory::Arithmetic]),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn shaped(id: u64, structure: ControlFlowGraph) -> FunctionFeatures {
    FunctionFeatures::with_structure(FunctionId(id), [], structure)
}

fn left_shapes() -> Vec<FunctionFeatures> {
    vec![
        shaped(0x1200, triangle()),
        shaped(0x1000, diamond(InstructionCategory::Load)),
        shaped(0x1100, diamond(InstructionCategory::Vector)),
        shaped(0x1300, diamond(InstructionCategory::Load)),
        features(0x1400, [DataReference::string_literal("only a reference")]),
    ]
}

fn right_shapes() -> Vec<FunctionFeatures> {
    vec![
        shaped(0x2100, diamond(InstructionCategory::Load)),
        shaped(0x2000, triangle()),
        features(0x2200, [DataReference::string_literal("only a reference")]),
        shaped(0x2300, diamond(InstructionCategory::Vector)),
    ]
}

fn left_corpus() -> Vec<FunctionFeatures> {
    vec![
        features(
            0x1300,
            [
                DataReference::string_literal("unsupported archive member"),
                DataReference::imported_call("inflateInit2"),
            ],
        ),
        features(0x1000, [DataReference::UnusualConstant(0x9e37_79b9)]),
        features(0x1100, [DataReference::string_literal("shared prologue")]),
        features(0x1200, [DataReference::string_literal("shared prologue")]),
        features(0x1400, []),
    ]
}

fn right_corpus() -> Vec<FunctionFeatures> {
    vec![
        features(0x2200, [DataReference::string_literal("shared prologue")]),
        features(
            0x2000,
            [
                DataReference::string_literal("unsupported archive member"),
                DataReference::imported_call("inflateInit2"),
            ],
        ),
        features(0x2100, [DataReference::UnusualConstant(0x9e37_79b9)]),
        features(0x2300, [DataReference::string_literal("shared prologue")]),
    ]
}

#[test]
fn repeated_runs_produce_an_identical_report() {
    let left: Vec<FunctionFeatures> = left_corpus();
    let right: Vec<FunctionFeatures> = right_corpus();

    let first: MatchReport = match_functions(&left, &right);
    let second: MatchReport = match_functions(&left, &right);
    let third: MatchReport = match_functions(&left, &right);

    assert_eq!(first, second);
    assert_eq!(second, third);
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
    assert_eq!(format!("{second:?}"), format!("{third:?}"));
}

#[test]
fn swapping_the_two_sides_mirrors_the_report() {
    let left: Vec<FunctionFeatures> = left_corpus();
    let right: Vec<FunctionFeatures> = right_corpus();

    let forward: MatchReport = match_functions(&left, &right);
    let reversed: MatchReport = match_functions(&right, &left);

    assert_eq!(forward.left, reversed.right);
    assert_eq!(forward.right, reversed.left);
    assert_eq!(forward.exact_count(), reversed.exact_count());
    let mirrored: Vec<(FunctionId, FunctionId)> = reversed
        .exact_pairs()
        .into_iter()
        .map(|(subject, counterpart): (FunctionId, FunctionId)| (counterpart, subject))
        .collect();
    let mut forward_pairs: Vec<(FunctionId, FunctionId)> = forward.exact_pairs();
    forward_pairs.sort_unstable();
    let mut mirrored_pairs: Vec<(FunctionId, FunctionId)> = mirrored;
    mirrored_pairs.sort_unstable();
    assert_eq!(forward_pairs, mirrored_pairs);
}

#[test]
fn the_order_of_the_inputs_does_not_change_the_report() {
    let left: Vec<FunctionFeatures> = left_corpus();
    let right: Vec<FunctionFeatures> = right_corpus();
    let reversed_left: Vec<FunctionFeatures> = left.iter().rev().cloned().collect();
    let reversed_right: Vec<FunctionFeatures> = right.iter().rev().cloned().collect();

    let baseline: MatchReport = match_functions(&left, &right);
    let permuted: MatchReport = match_functions(&reversed_left, &reversed_right);

    assert_eq!(baseline, permuted);
    assert_eq!(format!("{baseline:?}"), format!("{permuted:?}"));
}

#[test]
fn verdicts_are_ordered_by_subject_regardless_of_input_order() {
    let left: Vec<FunctionFeatures> = left_corpus();
    let right: Vec<FunctionFeatures> = right_corpus();

    let report: MatchReport = match_functions(&left, &right);

    let subjects: Vec<FunctionId> = report
        .left
        .iter()
        .map(|entry: &FunctionVerdict| entry.subject)
        .collect();
    let mut sorted: Vec<FunctionId> = subjects.clone();
    sorted.sort_unstable();
    assert_eq!(subjects, sorted);
    assert_eq!(
        subjects,
        vec![
            FunctionId(0x1000),
            FunctionId(0x1100),
            FunctionId(0x1200),
            FunctionId(0x1300),
            FunctionId(0x1400),
        ]
    );
}

#[test]
fn repeated_runs_over_a_shaped_corpus_produce_an_identical_report() {
    let left: Vec<FunctionFeatures> = left_shapes();
    let right: Vec<FunctionFeatures> = right_shapes();

    let first: MatchReport = match_functions(&left, &right);
    let second: MatchReport = match_functions(&left, &right);

    assert_eq!(first, second);
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
    assert_eq!(
        first.structural_pairs(),
        vec![
            (FunctionId(0x1100), FunctionId(0x2300)),
            (FunctionId(0x1200), FunctionId(0x2000)),
        ]
    );
    assert_eq!(
        first.exact_pairs(),
        vec![(FunctionId(0x1400), FunctionId(0x2200))]
    );
}

#[test]
fn swapping_the_two_sides_mirrors_a_shaped_report() {
    let left: Vec<FunctionFeatures> = left_shapes();
    let right: Vec<FunctionFeatures> = right_shapes();

    let forward: MatchReport = match_functions(&left, &right);
    let reversed: MatchReport = match_functions(&right, &left);

    assert_eq!(forward.left, reversed.right);
    assert_eq!(forward.right, reversed.left);
    assert_eq!(forward.matched_count(), reversed.matched_count());
}

#[test]
fn the_order_of_a_shaped_corpus_does_not_change_the_report() {
    let left: Vec<FunctionFeatures> = left_shapes();
    let right: Vec<FunctionFeatures> = right_shapes();
    let reversed_left: Vec<FunctionFeatures> = left.iter().rev().cloned().collect();
    let reversed_right: Vec<FunctionFeatures> = right.iter().rev().cloned().collect();

    let baseline: MatchReport = match_functions(&left, &right);
    let permuted: MatchReport = match_functions(&reversed_left, &reversed_right);

    assert_eq!(baseline, permuted);
    assert_eq!(format!("{baseline:?}"), format!("{permuted:?}"));
}

#[test]
fn candidate_sets_are_reported_in_canonical_order() {
    let left: Vec<FunctionFeatures> = vec![features(
        0x1000,
        [DataReference::string_literal("hot path")],
    )];
    let right: Vec<FunctionFeatures> = vec![
        features(0x2400, [DataReference::string_literal("hot path")]),
        features(0x2100, [DataReference::string_literal("hot path")]),
        features(0x2300, [DataReference::string_literal("hot path")]),
    ];

    let report: MatchReport = match_functions(&left, &right);

    let Some(Verdict::Ambiguous { candidates, .. }) = report.left_verdict(FunctionId(0x1000))
    else {
        panic!("expected an ambiguous verdict for the single left function");
    };
    let ordered: Vec<FunctionId> = candidates.iter().copied().collect();
    assert_eq!(
        ordered,
        vec![FunctionId(0x2100), FunctionId(0x2300), FunctionId(0x2400)]
    );
}
