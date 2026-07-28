use std::collections::BTreeSet;

use disrobe_similarity::{
    AnchorStrength, DataReference, FunctionFeatures, FunctionId, MatchReport, UnmatchedCause,
    Verdict, match_functions,
};

fn features<const N: usize>(id: u64, references: [DataReference; N]) -> FunctionFeatures {
    FunctionFeatures::new(FunctionId(id), references)
}

fn anchor_set<const N: usize>(references: [DataReference; N]) -> BTreeSet<DataReference> {
    BTreeSet::from(references)
}

fn parser_anchor() -> [DataReference; 2] {
    [
        DataReference::string_literal("invalid utf-8 at offset"),
        DataReference::imported_call("memcpy"),
    ]
}

fn candidates<const N: usize>(ids: [u64; N]) -> BTreeSet<FunctionId> {
    ids.into_iter().map(FunctionId).collect()
}

#[test]
fn a_third_function_carrying_the_same_anchor_refuses_the_match() {
    let left: Vec<FunctionFeatures> = vec![
        features(0x1000, parser_anchor()),
        features(0x3000, parser_anchor()),
    ];
    let right: Vec<FunctionFeatures> = vec![features(0x2000, parser_anchor())];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert!(report.exact_pairs().is_empty());
    for subject in [FunctionId(0x1000), FunctionId(0x3000)] {
        assert_eq!(
            report.left_verdict(subject),
            Some(&Verdict::Ambiguous {
                candidates: candidates([0x2000]),
                own_side: 2,
                other_side: 1,
            })
        );
    }
    assert_eq!(
        report.right_verdict(FunctionId(0x2000)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x1000, 0x3000]),
            own_side: 1,
            other_side: 2,
        })
    );
}

#[test]
fn a_third_function_on_the_other_side_also_refuses_the_match() {
    let left: Vec<FunctionFeatures> = vec![features(0x1000, parser_anchor())];
    let right: Vec<FunctionFeatures> = vec![
        features(0x2000, parser_anchor()),
        features(0x4000, parser_anchor()),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x2000, 0x4000]),
            own_side: 1,
            other_side: 2,
        })
    );
}

#[test]
fn an_anchor_repeated_on_both_sides_refuses_the_match() {
    let left: Vec<FunctionFeatures> = vec![
        features(0x1000, parser_anchor()),
        features(0x1100, parser_anchor()),
    ];
    let right: Vec<FunctionFeatures> = vec![
        features(0x2000, parser_anchor()),
        features(0x2200, parser_anchor()),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x2000, 0x2200]),
            own_side: 2,
            other_side: 2,
        })
    );
}

#[test]
fn an_anchor_unique_on_both_sides_matches_exactly() {
    let left: Vec<FunctionFeatures> = vec![features(0x1000, parser_anchor())];
    let right: Vec<FunctionFeatures> = vec![features(0x2000, parser_anchor())];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 1);
    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Exact {
            counterpart: FunctionId(0x2000),
            shared_references: anchor_set(parser_anchor()),
            strength: AnchorStrength::Distinctive,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(0x2000)),
        Some(&Verdict::Exact {
            counterpart: FunctionId(0x1000),
            shared_references: anchor_set(parser_anchor()),
            strength: AnchorStrength::Distinctive,
        })
    );
}

#[test]
fn a_strict_subset_of_another_anchor_does_not_match_it() {
    let left: Vec<FunctionFeatures> = vec![features(
        0x1000,
        [
            DataReference::string_literal("unexpected end of stream"),
            DataReference::imported_call("fread"),
        ],
    )];
    let right: Vec<FunctionFeatures> = vec![features(
        0x2000,
        [DataReference::string_literal("unexpected end of stream")],
    )];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        })
    );
    assert_eq!(
        report.right_verdict(FunctionId(0x2000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        })
    );
}

#[test]
fn a_strict_superset_of_another_anchor_does_not_match_it() {
    let left: Vec<FunctionFeatures> = vec![features(
        0x1000,
        [DataReference::string_literal("connection reset by peer")],
    )];
    let right: Vec<FunctionFeatures> = vec![features(
        0x2000,
        [
            DataReference::string_literal("connection reset by peer"),
            DataReference::string_literal("retrying in %u ms"),
        ],
    )];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        })
    );
}

#[test]
fn twenty_functions_referencing_nothing_produce_zero_matches() {
    let population: u64 = 20;
    let left: Vec<FunctionFeatures> = (0..population)
        .map(|index: u64| features(0x1000 + index, []))
        .collect();
    let right: Vec<FunctionFeatures> = (0..population)
        .map(|index: u64| features(0x2000 + index, []))
        .collect();

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert!(report.exact_pairs().is_empty());
    assert_eq!(report.left.len(), population as usize);
    assert_eq!(report.right.len(), population as usize);
    for entry in report.left.iter().chain(report.right.iter()) {
        assert_eq!(
            entry.verdict,
            Verdict::Unmatched {
                cause: UnmatchedCause::NoAnchor,
            }
        );
    }
}

#[test]
fn an_empty_anchor_is_refused_even_when_it_is_unique_on_both_sides() {
    let left: Vec<FunctionFeatures> = vec![features(0x1000, [])];
    let right: Vec<FunctionFeatures> = vec![features(0x2000, [])];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
}

#[test]
fn an_ordinary_constant_never_anchors_a_match_on_its_own() {
    let ordinary: [u64; 8] = [
        0,
        1,
        4,
        0x100,
        0x1000,
        0xffff_ffff,
        0xffff_f000,
        0x5555_5555,
    ];
    for value in ordinary {
        let left: Vec<FunctionFeatures> =
            vec![features(0x1000, [DataReference::UnusualConstant(value)])];
        let right: Vec<FunctionFeatures> =
            vec![features(0x2000, [DataReference::UnusualConstant(value)])];

        let report: MatchReport = match_functions(&left, &right);

        assert_eq!(report.exact_count(), 0, "value {value:#x} anchored a match");
        assert_eq!(
            report.left_verdict(FunctionId(0x1000)),
            Some(&Verdict::Unmatched {
                cause: UnmatchedCause::NoAnchor,
            })
        );
    }
}

#[test]
fn an_ordinary_constant_does_not_dilute_a_real_anchor() {
    let left: Vec<FunctionFeatures> = vec![features(
        0x1000,
        [
            DataReference::UnusualConstant(0x9e37_79b9),
            DataReference::UnusualConstant(1),
        ],
    )];
    let right: Vec<FunctionFeatures> = vec![features(
        0x2000,
        [DataReference::UnusualConstant(0x9e37_79b9)],
    )];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
}

#[test]
fn a_single_unusual_constant_anchors_a_match() {
    let left: Vec<FunctionFeatures> = vec![
        features(0x1000, [DataReference::UnusualConstant(0xdead_beef)]),
        features(0x1100, [DataReference::UnusualConstant(0xcafe_babe)]),
    ];
    let right: Vec<FunctionFeatures> = vec![
        features(0x2000, [DataReference::UnusualConstant(0xcafe_babe)]),
        features(0x2200, [DataReference::UnusualConstant(0xdead_beef)]),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.exact_pairs(),
        vec![
            (FunctionId(0x1000), FunctionId(0x2200)),
            (FunctionId(0x1100), FunctionId(0x2000)),
        ]
    );
}

#[test]
fn a_named_import_call_anchors_a_match_and_a_nameless_one_does_not() {
    let left: Vec<FunctionFeatures> = vec![
        features(0x1000, [DataReference::imported_call("BCryptGenRandom")]),
        features(0x1100, [DataReference::imported_call("")]),
    ];
    let right: Vec<FunctionFeatures> = vec![
        features(0x2000, [DataReference::imported_call("BCryptGenRandom")]),
        features(0x2200, [DataReference::imported_call("")]),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
}

#[test]
fn an_id_repeated_on_its_own_side_is_reported_once_and_never_matches() {
    let left: Vec<FunctionFeatures> = vec![
        features(0x1000, parser_anchor()),
        features(0x1000, [DataReference::string_literal("other")]),
    ];
    let right: Vec<FunctionFeatures> = vec![features(0x2000, parser_anchor())];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.exact_count(), 0);
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
            cause: UnmatchedCause::NoCandidate,
        })
    );
}

#[test]
fn an_empty_other_side_leaves_every_anchored_function_without_a_candidate() {
    let left: Vec<FunctionFeatures> = vec![features(0x1000, parser_anchor())];
    let right: Vec<FunctionFeatures> = Vec::new();

    let report: MatchReport = match_functions(&left, &right);

    assert!(report.right.is_empty());
    assert_eq!(
        report.left_verdict(FunctionId(0x1000)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        })
    );
}

#[test]
fn every_function_receives_exactly_one_verdict_in_a_mixed_corpus() {
    let left: Vec<FunctionFeatures> = vec![
        features(0x1000, parser_anchor()),
        features(0x1100, [DataReference::string_literal("shared prologue")]),
        features(0x1200, [DataReference::string_literal("shared prologue")]),
        features(0x1300, [DataReference::string_literal("left only")]),
        features(0x1400, []),
    ];
    let right: Vec<FunctionFeatures> = vec![
        features(0x2000, parser_anchor()),
        features(0x2100, [DataReference::string_literal("shared prologue")]),
        features(0x2200, [DataReference::string_literal("right only")]),
    ];

    let report: MatchReport = match_functions(&left, &right);

    assert_eq!(report.left.len(), left.len());
    assert_eq!(report.right.len(), right.len());
    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))]
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1100)),
        Some(&Verdict::Ambiguous {
            candidates: candidates([0x2100]),
            own_side: 2,
            other_side: 1,
        })
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1300)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        })
    );
    assert_eq!(
        report.left_verdict(FunctionId(0x1400)),
        Some(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        })
    );
    assert_eq!(report.left_verdict(FunctionId(0x9999)), None);
}
