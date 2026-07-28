#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_similarity::{
    AnchorStrength, BasicBlock, ControlFlowGraph, DataReference, FunctionFeatures, FunctionId,
    InstructionCategory, MatchReport, MatchStage, UnmatchedCause, Verdict, match_functions,
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

fn diamond(tail: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([3], [InstructionCategory::Load]),
            block([3], [InstructionCategory::Store]),
            block([], [tail]),
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

fn anchored<const N: usize>(
    id: u64,
    references: [DataReference; N],
    structure: ControlFlowGraph,
) -> FunctionFeatures {
    FunctionFeatures::with_structure(FunctionId(id), references, structure)
}

fn candidates<const N: usize>(ids: [u64; N]) -> BTreeSet<FunctionId> {
    ids.into_iter().map(FunctionId).collect()
}

#[test]
fn a_function_matched_by_its_references_is_not_matched_again_by_its_shape() {
    let anchor: DataReference = DataReference::string_literal("invalid utf-8 at offset");
    let left: Vec<FunctionFeatures> = vec![
        anchored(
            0x1000,
            [anchor.clone()],
            diamond(InstructionCategory::Return),
        ),
        anchored(0x1100, [], diamond(InstructionCategory::Return)),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(
            0x2000,
            [anchor.clone()],
            diamond(InstructionCategory::Return),
        ),
        anchored(0x2100, [], diamond(InstructionCategory::Return)),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Exact {
            counterpart: FunctionId(0x2000),
            shared_references: BTreeSet::from([anchor]),
            strength: AnchorStrength::Distinctive,
        }),
        "the reference stage runs first and its evidence survives the structural stage"
    );
    assert_eq!(
        report
            .left_verdict(FunctionId(0x1000))
            .and_then(Verdict::stage),
        Some(MatchStage::DataReference)
    );
    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
    assert_eq!(
        report.structural_pairs(),
        vec![(FunctionId(0x1100), FunctionId(0x2100))],
        "the shape held by four functions becomes unique once the reference pair is taken out"
    );
    assert_eq!(
        report.matched_pairs(),
        vec![
            (FunctionId(0x1000), FunctionId(0x2000)),
            (FunctionId(0x1100), FunctionId(0x2100)),
        ]
    );
    assert_eq!(report.exact_count(), 1);
    assert_eq!(report.structural_count(), 1);
    assert_eq!(report.matched_count(), 2);
}

#[test]
fn a_shape_shared_with_a_reference_matched_function_still_refuses_a_third_holder() {
    let anchor: DataReference = DataReference::string_literal("frame header too short");
    let left: Vec<FunctionFeatures> = vec![
        anchored(
            0x1000,
            [anchor.clone()],
            diamond(InstructionCategory::Return),
        ),
        anchored(0x1100, [], diamond(InstructionCategory::Return)),
        anchored(0x1200, [], diamond(InstructionCategory::Return)),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, [anchor], diamond(InstructionCategory::Return)),
        anchored(0x2100, [], diamond(InstructionCategory::Return)),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 1);
    assert_eq!(report.structural_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x2100]),
            own_side: 2,
            other_side: 1,
        })
    );
}

#[test]
fn a_shape_resolves_a_function_the_reference_stage_left_ambiguous() {
    let shared: DataReference = DataReference::string_literal("shared prologue");
    let left: Vec<FunctionFeatures> = vec![
        anchored(
            0x1000,
            [shared.clone()],
            diamond(InstructionCategory::Return),
        ),
        anchored(0x1100, [shared.clone()], triangle()),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(
            0x2000,
            [shared.clone()],
            diamond(InstructionCategory::Return),
        ),
        anchored(0x2100, [shared], triangle()),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.structural_pairs(),
        vec![
            (FunctionId(0x1000), FunctionId(0x2000)),
            (FunctionId(0x1100), FunctionId(0x2100)),
        ]
    );
}

#[test]
fn a_reference_ambiguity_is_not_replaced_by_a_shape_ambiguity() {
    let shared: DataReference = DataReference::string_literal("shared prologue");
    let left: Vec<FunctionFeatures> = vec![
        anchored(
            0x1000,
            [shared.clone()],
            diamond(InstructionCategory::Return),
        ),
        anchored(
            0x1100,
            [shared.clone()],
            diamond(InstructionCategory::Return),
        ),
    ];
    let right: Vec<FunctionFeatures> = vec![anchored(
        0x2000,
        [shared],
        diamond(InstructionCategory::Return),
    )];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.matched_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x2000]),
            own_side: 2,
            other_side: 1,
        }),
        "the reference stage already named the candidates, the shape stage adds nothing here"
    );
}

#[test]
fn a_repeated_function_id_is_never_matched_by_its_shape() {
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, [], diamond(InstructionCategory::Return)),
        anchored(0x1000, [], triangle()),
    ];
    let right: Vec<FunctionFeatures> =
        vec![anchored(0x2000, [], diamond(InstructionCategory::Return))];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.matched_count(), 0);
    assert_eq!(report.left.len(), 1);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::DuplicateFunctionId,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(0x2000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
}

#[test]
fn the_structure_a_function_carries_is_readable_back() {
    let shape: ControlFlowGraph = triangle();
    let bare: FunctionFeatures = FunctionFeatures::new(FunctionId(0x1000), []);
    let carried: FunctionFeatures =
        FunctionFeatures::with_structure(FunctionId(0x1100), [], shape.clone());

    assert_eq!(bare.structure(), None);
    assert_eq!(bare.structural_key(), None);
    assert_eq!(carried.structure(), Some(&shape));
    assert_eq!(carried.structural_key(), shape.structural_key());
}
