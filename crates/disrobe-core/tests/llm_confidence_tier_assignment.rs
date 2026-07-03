#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_core::{
    ConfidenceTier, PassRecovery, RECOVERY_SCHEMA, RecoveryReport, RecoverySignal, TierHistogram,
    assign_tier,
};
use serde_json::{Value, json};

#[test]
fn each_signal_maps_to_documented_tier() {
    assert_eq!(
        assign_tier(RecoverySignal::ByteRoundtripVerified),
        ConfidenceTier::Exact
    );
    assert_eq!(
        assign_tier(RecoverySignal::RecompilesEquivalent),
        ConfidenceTier::Semantic
    );
    assert_eq!(
        assign_tier(RecoverySignal::FullBodyLifted),
        ConfidenceTier::Semantic
    );
    assert_eq!(
        assign_tier(RecoverySignal::SomeBodiesLifted),
        ConfidenceTier::Partial
    );
    assert_eq!(
        assign_tier(RecoverySignal::StructuredNoVerify),
        ConfidenceTier::Partial
    );
    assert_eq!(
        assign_tier(RecoverySignal::SignaturesOnly),
        ConfidenceTier::Skeleton
    );
    assert_eq!(
        assign_tier(RecoverySignal::NoRecovery),
        ConfidenceTier::Skeleton
    );
}

#[test]
fn exact_is_reachable_only_via_byte_roundtrip() {
    let exact_signals: Vec<RecoverySignal> = vec![
        RecoverySignal::ByteRoundtripVerified,
        RecoverySignal::RecompilesEquivalent,
        RecoverySignal::FullBodyLifted,
        RecoverySignal::SomeBodiesLifted,
        RecoverySignal::StructuredNoVerify,
        RecoverySignal::SignaturesOnly,
        RecoverySignal::NoRecovery,
    ]
    .into_iter()
    .filter(|s: &RecoverySignal| assign_tier(*s) == ConfidenceTier::Exact)
    .collect();
    assert_eq!(exact_signals, vec![RecoverySignal::ByteRoundtripVerified]);
}

#[test]
fn ordering_and_rank_are_weakest_first() {
    assert!(ConfidenceTier::Exact > ConfidenceTier::Semantic);
    assert!(ConfidenceTier::Semantic > ConfidenceTier::Partial);
    assert!(ConfidenceTier::Partial > ConfidenceTier::Skeleton);

    assert_eq!(ConfidenceTier::Exact.rank(), 3);
    assert_eq!(ConfidenceTier::Semantic.rank(), 2);
    assert_eq!(ConfidenceTier::Partial.rank(), 1);
    assert_eq!(ConfidenceTier::Skeleton.rank(), 0);

    for rank in 0u8..=3 {
        let tier: ConfidenceTier = ConfidenceTier::from_rank(rank).expect("valid rank");
        assert_eq!(tier.rank(), rank);
    }
    assert_eq!(ConfidenceTier::from_rank(4), None);
}

#[test]
fn tier_serde_is_lowercase() {
    assert_eq!(
        serde_json::to_value(ConfidenceTier::Exact).unwrap(),
        json!("exact")
    );
    assert_eq!(
        serde_json::to_value(ConfidenceTier::Semantic).unwrap(),
        json!("semantic")
    );
    assert_eq!(
        serde_json::to_value(ConfidenceTier::Partial).unwrap(),
        json!("partial")
    );
    assert_eq!(
        serde_json::to_value(ConfidenceTier::Skeleton).unwrap(),
        json!("skeleton")
    );

    let back: ConfidenceTier = serde_json::from_value(json!("skeleton")).unwrap();
    assert_eq!(back, ConfidenceTier::Skeleton);
}

#[test]
fn from_tiers_folds_real_counts() {
    let tiers: [ConfidenceTier; 7] = [
        ConfidenceTier::Exact,
        ConfidenceTier::Exact,
        ConfidenceTier::Semantic,
        ConfidenceTier::Partial,
        ConfidenceTier::Partial,
        ConfidenceTier::Partial,
        ConfidenceTier::Skeleton,
    ];
    let histogram: TierHistogram = TierHistogram::from_tiers(tiers);
    assert_eq!(histogram.exact, 2);
    assert_eq!(histogram.semantic, 1);
    assert_eq!(histogram.partial, 3);
    assert_eq!(histogram.skeleton, 1);
    assert_eq!(histogram.total(), 7);
    assert_eq!(histogram.get(ConfidenceTier::Partial), 3);
}

#[test]
fn report_histogram_matches_folded_passes() {
    let raw: Vec<(&str, RecoverySignal, u32, u64)> = vec![
        (
            "py-decompile::a",
            RecoverySignal::ByteRoundtripVerified,
            12,
            40,
        ),
        (
            "py-decompile::b",
            RecoverySignal::ByteRoundtripVerified,
            8,
            15,
        ),
        (
            "py-decompile::c",
            RecoverySignal::RecompilesEquivalent,
            5,
            22,
        ),
        ("nuitka::body-a", RecoverySignal::SomeBodiesLifted, 3, 9),
        ("nuitka::body-b", RecoverySignal::StructuredNoVerify, 2, 4),
        ("nuitka::body-c", RecoverySignal::SomeBodiesLifted, 1, 7),
        ("nuitka::surface", RecoverySignal::SignaturesOnly, 6, 3),
    ];
    let passes: Vec<PassRecovery> = raw
        .iter()
        .map(
            |(id, signal, units, ms): &(&str, RecoverySignal, u32, u64)| PassRecovery {
                pass_id: (*id).to_owned(),
                tier: assign_tier(*signal),
                unit_count: *units,
                duration_ms: *ms,
            },
        )
        .collect();

    let report: RecoveryReport =
        RecoveryReport::new(Some("file:///sample.pyc".to_owned()), passes.clone());

    assert_eq!(report.histogram.exact, 2);
    assert_eq!(report.histogram.semantic, 1);
    assert_eq!(report.histogram.partial, 3);
    assert_eq!(report.histogram.skeleton, 1);
    assert_eq!(report.histogram.total(), passes.len() as u32);
    assert_eq!(report.total_duration_ms, 40 + 15 + 22 + 9 + 4 + 7 + 3);
    assert_eq!(report.min_tier(), Some(ConfidenceTier::Skeleton));
    assert_eq!(report.max_tier(), Some(ConfidenceTier::Exact));
    assert_eq!(report.schema, RECOVERY_SCHEMA);
}

#[test]
fn report_serde_round_trips() {
    let passes: Vec<PassRecovery> = vec![
        PassRecovery {
            pass_id: "py-decompile::main".to_owned(),
            tier: assign_tier(RecoverySignal::ByteRoundtripVerified),
            unit_count: 4,
            duration_ms: 11,
        },
        PassRecovery {
            pass_id: "py-decompile::dup".to_owned(),
            tier: assign_tier(RecoverySignal::ByteRoundtripVerified),
            unit_count: 2,
            duration_ms: 6,
        },
        PassRecovery {
            pass_id: "nuitka::skeleton".to_owned(),
            tier: assign_tier(RecoverySignal::NoRecovery),
            unit_count: 1,
            duration_ms: 2,
        },
    ];
    let report: RecoveryReport = RecoveryReport::new(None, passes);

    let value: Value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["schema"], json!(RECOVERY_SCHEMA));
    assert_eq!(value["histogram"]["exact"], json!(2));
    assert_eq!(value["histogram"]["skeleton"], json!(1));
    assert!(value.get("uri").is_none());

    let back: RecoveryReport = serde_json::from_value(value).unwrap();
    assert_eq!(back, report);
}
