#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_similarity::{
    AnchorStrength, BasicBlock, CallRelation, ControlFlowGraph, DataReference, FunctionFeatures,
    FunctionId, InstructionCategory, MAXIMUM_PROPAGATION_HOPS, MatchReport, MatchStage,
    StructuralKey, UnmatchedCause, Verdict, match_functions,
};

const IMAGE_DELTA: u64 = 0x1000;

fn block<const N: usize, const M: usize>(
    successors: [usize; N],
    categories: [InstructionCategory; M],
) -> BasicBlock {
    BasicBlock::new(successors, categories)
}

fn graph(entry: usize, blocks: Vec<BasicBlock>) -> ControlFlowGraph {
    ControlFlowGraph::new(entry, blocks).expect("the fixture graph is well formed")
}

fn leaf(category: InstructionCategory) -> ControlFlowGraph {
    graph(0, vec![block([], [category, InstructionCategory::Return])])
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

fn triangle(arm: InstructionCategory) -> ControlFlowGraph {
    graph(
        0,
        vec![
            block(
                [1, 2],
                [InstructionCategory::Compare, InstructionCategory::Branch],
            ),
            block([2], [arm]),
            block([], [InstructionCategory::Return]),
        ],
    )
}

fn agreement(category: InstructionCategory) -> StructuralKey {
    leaf(category)
        .corroborating_key()
        .expect("a single block carrying instructions corroborates a position")
}

fn anchored<const N: usize>(id: u64, text: &str, calls: [u64; N]) -> FunctionFeatures {
    FunctionFeatures::with_structure(
        FunctionId(id),
        [DataReference::string_literal(text)],
        diamond(),
    )
    .calling(calls.into_iter().map(FunctionId))
}

fn shaped<const N: usize>(
    id: u64,
    structure: ControlFlowGraph,
    calls: [u64; N],
) -> FunctionFeatures {
    FunctionFeatures::with_structure(FunctionId(id), [], structure)
        .calling(calls.into_iter().map(FunctionId))
}

fn small<const N: usize>(
    id: u64,
    category: InstructionCategory,
    calls: [u64; N],
) -> FunctionFeatures {
    shaped(id, leaf(category), calls)
}

fn bare<const N: usize>(id: u64, calls: [u64; N]) -> FunctionFeatures {
    FunctionFeatures::new(FunctionId(id), []).calling(calls.into_iter().map(FunctionId))
}

fn propagated(
    counterpart: u64,
    anchor: u64,
    anchor_counterpart: u64,
    relation: CallRelation,
    hops: u32,
    category: InstructionCategory,
) -> Verdict {
    Verdict::Propagated {
        counterpart: FunctionId(counterpart),
        anchor: FunctionId(anchor),
        anchor_counterpart: FunctionId(anchor_counterpart),
        relation,
        hops,
        agreement: agreement(category),
    }
}

#[test]
fn a_uniquely_positioned_callee_with_no_structure_to_corroborate_it_is_not_matched() {
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100]),
        bare(0x1100, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100]),
        bare(0x2100, []),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))],
        "the anchor pair the propagation would derive from must exist"
    );
    assert_eq!(
        report.propagated_count(),
        0,
        "a position with nothing to corroborate it must never assert a match"
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(0x2100)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
}

#[test]
fn a_uniquely_positioned_callee_whose_structure_disagrees_is_not_matched() {
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100]),
        small(0x1100, InstructionCategory::Arithmetic, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100]),
        small(0x2100, InstructionCategory::Logic, []),
    ];

    assert_ne!(
        agreement(InstructionCategory::Arithmetic),
        agreement(InstructionCategory::Logic),
        "the two fixtures must disagree, otherwise this proves nothing"
    );

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 1);
    assert_eq!(
        report.propagated_count(),
        0,
        "the position is forced but the structures disagree, so the pair is refused"
    );
}

#[test]
fn a_uniquely_positioned_callee_that_agrees_structurally_is_matched() {
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100]),
        small(0x1100, InstructionCategory::Arithmetic, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100]),
        small(0x2100, InstructionCategory::Arithmetic, []),
    ];

    assert_eq!(
        leaf(InstructionCategory::Arithmetic).structural_key(),
        None,
        "the callee must be out of reach of the control-flow stage, or this proves nothing"
    );

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.propagated_pairs(),
        vec![(FunctionId(0x1100), FunctionId(0x2100))]
    );
    assert_eq!(report.structural_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&propagated(
            0x2100,
            0x1000,
            0x2000,
            CallRelation::Callee,
            1,
            InstructionCategory::Arithmetic,
        ))
    );
    assert_eq!(
        report.right_verdict(FunctionId(0x2100)),
        Some(&propagated(
            0x1100,
            0x2000,
            0x1000,
            CallRelation::Callee,
            1,
            InstructionCategory::Arithmetic,
        ))
    );
    assert_eq!(
        report
            .left_verdict(FunctionId(0x1100))
            .and_then(Verdict::stage),
        Some(MatchStage::Propagation)
    );
    assert_eq!(
        report.matched_pairs(),
        vec![
            (FunctionId(0x1000), FunctionId(0x2000)),
            (FunctionId(0x1100), FunctionId(0x2100)),
        ]
    );
}

#[test]
fn a_caller_of_a_matched_function_propagates_by_the_same_rule() {
    let left: Vec<FunctionFeatures> = vec![
        small(0x1000, InstructionCategory::Arithmetic, [0x1100]),
        anchored(0x1100, "chunk table exhausted", []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        small(0x2000, InstructionCategory::Arithmetic, [0x2100]),
        anchored(0x2100, "chunk table exhausted", []),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.propagated_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&propagated(
            0x2000,
            0x1100,
            0x2100,
            CallRelation::Caller,
            1,
            InstructionCategory::Arithmetic,
        ))
    );
}

#[test]
fn a_caller_with_two_indistinguishable_callees_propagates_to_neither() {
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100, 0x1200]),
        small(0x1100, InstructionCategory::Arithmetic, []),
        small(0x1200, InstructionCategory::Arithmetic, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100, 0x2200]),
        small(0x2100, InstructionCategory::Arithmetic, []),
        small(0x2200, InstructionCategory::Arithmetic, []),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 1);
    assert_eq!(
        report.propagated_count(),
        0,
        "two callees that cannot be told apart make the position ambiguous, so neither is taken"
    );
    for subject in [0x1100_u64, 0x1200] {
        assert_eq!(
            report.left_verdict(FunctionId(subject)),
            Some(&Verdict::Unmatched {
                cause: UnmatchedCause::NoAnchor,
            })
        );
    }
}

#[test]
fn one_of_two_indistinguishable_callees_is_taken_once_the_other_is_matched() {
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100, 0x1200]),
        FunctionFeatures::with_structure(
            FunctionId(0x1100),
            [DataReference::string_literal("frame header too short")],
            leaf(InstructionCategory::Arithmetic),
        ),
        small(0x1200, InstructionCategory::Arithmetic, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100, 0x2200]),
        FunctionFeatures::with_structure(
            FunctionId(0x2100),
            [DataReference::string_literal("frame header too short")],
            leaf(InstructionCategory::Arithmetic),
        ),
        small(0x2200, InstructionCategory::Arithmetic, []),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.exact_pairs(),
        vec![
            (FunctionId(0x1000), FunctionId(0x2000)),
            (FunctionId(0x1100), FunctionId(0x2100)),
        ]
    );
    assert_eq!(
        report.propagated_pairs(),
        vec![(FunctionId(0x1200), FunctionId(0x2200))],
        "with its twin already matched the remaining callee is forced"
    );
}

#[test]
fn a_function_matched_by_an_earlier_stage_keeps_its_own_evidence() {
    let reference: DataReference = DataReference::string_literal("frame header too short");
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100, 0x1200]),
        FunctionFeatures::with_structure(
            FunctionId(0x1100),
            [reference.clone()],
            leaf(InstructionCategory::Arithmetic),
        ),
        shaped(0x1200, triangle(InstructionCategory::Shift), []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100, 0x2200]),
        FunctionFeatures::with_structure(
            FunctionId(0x2100),
            [reference.clone()],
            leaf(InstructionCategory::Arithmetic),
        ),
        shaped(0x2200, triangle(InstructionCategory::Shift), []),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.propagated_count(),
        0,
        "both callees were already matched, so propagation has nothing to claim"
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&Verdict::Exact {
            counterpart: FunctionId(0x2100),
            shared_references: BTreeSet::from([reference]),
            strength: AnchorStrength::Distinctive,
        })
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1200)),
        Some(&Verdict::Structural {
            counterpart: FunctionId(0x2200),
            fingerprint: triangle(InstructionCategory::Shift).fingerprint(),
            instruction_mix: triangle(InstructionCategory::Shift).instruction_mix(),
        })
    );
}

#[test]
fn a_position_beyond_the_hop_bound_names_its_candidate_instead_of_asserting_it() {
    assert_eq!(
        MAXIMUM_PROPAGATION_HOPS, 2,
        "this fixture is a chain built around the bound"
    );
    let left: Vec<FunctionFeatures> = vec![
        anchored(0x1000, "record layout mismatch", [0x1100]),
        small(0x1100, InstructionCategory::Arithmetic, [0x1200]),
        small(0x1200, InstructionCategory::Logic, [0x1300]),
        small(0x1300, InstructionCategory::Shift, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        anchored(0x2000, "record layout mismatch", [0x2100]),
        small(0x2100, InstructionCategory::Arithmetic, [0x2200]),
        small(0x2200, InstructionCategory::Logic, [0x2300]),
        small(0x2300, InstructionCategory::Shift, []),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.propagated_pairs(),
        vec![
            (FunctionId(0x1100), FunctionId(0x2100)),
            (FunctionId(0x1200), FunctionId(0x2200)),
        ]
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&propagated(
            0x2100,
            0x1000,
            0x2000,
            CallRelation::Callee,
            1,
            InstructionCategory::Arithmetic,
        ))
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1200)),
        Some(&propagated(
            0x2200,
            0x1100,
            0x2100,
            CallRelation::Callee,
            2,
            InstructionCategory::Logic,
        ))
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1300)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(0x2300)]),
            own_side: 1,
            other_side: 1,
        }),
        "one hop past the bound the chain carries no direct evidence, so it degrades"
    );
    assert_eq!(
        report.right_verdict(FunctionId(0x2300)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(0x1300)]),
            own_side: 1,
            other_side: 1,
        })
    );
}

fn planted_left() -> Vec<FunctionFeatures> {
    vec![
        anchored(0x1000, "alpha stream truncated", [0x1100]),
        small(0x1100, InstructionCategory::Arithmetic, []),
        anchored(0x1500, "beta stream truncated", [0x1600, 0x1610]),
        small(0x1600, InstructionCategory::Logic, [0x1700]),
        small(0x1610, InstructionCategory::Shift, []),
        small(0x1700, InstructionCategory::Move, [0x1800]),
        small(0x1800, InstructionCategory::Compare, []),
    ]
}

fn planted_right() -> Vec<FunctionFeatures> {
    vec![
        anchored(0x2000, "alpha stream truncated", [0x2100]),
        small(0x2100, InstructionCategory::Arithmetic, []),
        anchored(0x2900, "beta stream truncated", [0x2a00, 0x2a10]),
        small(0x2a00, InstructionCategory::Logic, [0x2b00]),
        small(0x2a10, InstructionCategory::Vector, []),
        small(0x2b00, InstructionCategory::Move, [0x2c00]),
        small(0x2c00, InstructionCategory::Compare, []),
    ]
}

#[test]
fn one_wrong_anchor_does_not_cascade_past_the_bound() {
    let left: Vec<FunctionFeatures> = planted_left();
    let right: Vec<FunctionFeatures> = planted_right();

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.exact_pairs(),
        vec![
            (FunctionId(0x1000), FunctionId(0x2000)),
            (FunctionId(0x1500), FunctionId(0x2900)),
        ],
        "the fixture plants a wrong anchor by giving two unrelated functions one reference"
    );

    let wrong: Vec<(FunctionId, FunctionId)> = report
        .propagated_pairs()
        .into_iter()
        .filter(|(subject, counterpart): &(FunctionId, FunctionId)| {
            counterpart.0 != subject.0.wrapping_add(IMAGE_DELTA)
        })
        .collect();

    assert_eq!(
        wrong,
        vec![
            (FunctionId(0x1600), FunctionId(0x2a00)),
            (FunctionId(0x1700), FunctionId(0x2b00)),
        ],
        "the damage is the two corroborated neighbours inside the bound, and nothing else"
    );
    assert_eq!(
        report.propagated_pairs(),
        vec![
            (FunctionId(0x1100), FunctionId(0x2100)),
            (FunctionId(0x1600), FunctionId(0x2a00)),
            (FunctionId(0x1700), FunctionId(0x2b00)),
        ],
        "the correctly anchored neighbourhood is untouched by the planted anchor"
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1610)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        }),
        "the sibling whose counterpart does not agree structurally is refused"
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1800)),
        Some(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(0x2c00)]),
            own_side: 1,
            other_side: 1,
        }),
        "the third ring is past the bound, so the cascade stops there"
    );
}

#[test]
fn a_propagating_corpus_matches_itself_onto_itself() {
    let left: Vec<FunctionFeatures> = planted_left();

    let report: MatchReport = match_functions(&left, &left);

    for (subject, counterpart) in report.matched_pairs() {
        assert_eq!(
            subject, counterpart,
            "an image matched against itself must map every function to its own address"
        );
    }
    assert!(report.propagated_count() > 0);
}
