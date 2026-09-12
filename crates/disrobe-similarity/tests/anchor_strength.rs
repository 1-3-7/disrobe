use disrobe_similarity::{
    AnchorStrength, DataReference, FunctionFeatures, FunctionId, MatchReport, Verdict,
    match_functions,
};

fn features<const N: usize>(id: u64, references: [DataReference; N]) -> FunctionFeatures {
    FunctionFeatures::new(FunctionId(id), references)
}

fn strength_of(left: FunctionFeatures, right: FunctionFeatures) -> Option<AnchorStrength> {
    let report: MatchReport = match_functions(&[left], &[right]);
    match report.left_verdict(FunctionId(0x1000)) {
        Some(&Verdict::Exact { strength, .. }) => Some(strength),
        _ => None,
    }
}

#[test]
fn a_match_carried_by_one_imported_call_is_reported_as_the_weaker_kind() {
    let strength: Option<AnchorStrength> = strength_of(
        features(0x1000, [DataReference::imported_call("BCryptGenRandom")]),
        features(0x2000, [DataReference::imported_call("BCryptGenRandom")]),
    );
    assert_eq!(
        strength,
        Some(AnchorStrength::SingleImportedCall),
        "an import name is drawn from a vocabulary shared by every program, so one of them alone \
         can be unique by coincidence and the verdict must say so"
    );
}

#[test]
fn a_match_carried_by_one_string_is_reported_as_distinctive() {
    let strength: Option<AnchorStrength> = strength_of(
        features(
            0x1000,
            [DataReference::string_literal("invalid utf-8 at offset")],
        ),
        features(
            0x2000,
            [DataReference::string_literal("invalid utf-8 at offset")],
        ),
    );
    assert_eq!(
        strength,
        Some(AnchorStrength::Distinctive),
        "a string literal originates in the program's own source, so one is enough"
    );
}

#[test]
fn a_match_carried_by_one_unusual_constant_is_reported_as_distinctive() {
    let strength: Option<AnchorStrength> = strength_of(
        features(0x1000, [DataReference::UnusualConstant(0x9e37_79b9)]),
        features(0x2000, [DataReference::UnusualConstant(0x9e37_79b9)]),
    );
    assert_eq!(strength, Some(AnchorStrength::Distinctive));
}

#[test]
fn two_references_are_distinctive_even_when_one_is_an_import() {
    let strength: Option<AnchorStrength> = strength_of(
        features(
            0x1000,
            [
                DataReference::imported_call("memcpy"),
                DataReference::string_literal("frame header too short"),
            ],
        ),
        features(
            0x2000,
            [
                DataReference::imported_call("memcpy"),
                DataReference::string_literal("frame header too short"),
            ],
        ),
    );
    assert_eq!(
        strength,
        Some(AnchorStrength::Distinctive),
        "a second reference removes the coincidence, whatever kinds the pair are"
    );
}

#[test]
fn two_imported_calls_together_are_distinctive() {
    let strength: Option<AnchorStrength> = strength_of(
        features(
            0x1000,
            [
                DataReference::imported_call("BCryptGenRandom"),
                DataReference::imported_call("BCryptCloseAlgorithmProvider"),
            ],
        ),
        features(
            0x2000,
            [
                DataReference::imported_call("BCryptGenRandom"),
                DataReference::imported_call("BCryptCloseAlgorithmProvider"),
            ],
        ),
    );
    assert_eq!(strength, Some(AnchorStrength::Distinctive));
}

#[test]
fn the_weaker_kind_is_still_a_match_and_still_names_its_counterpart() {
    let report: MatchReport = match_functions(
        &[features(0x1000, [DataReference::imported_call("memcpy")])],
        &[features(0x2000, [DataReference::imported_call("memcpy")])],
    );
    assert_eq!(
        report.exact_pairs(),
        vec![(FunctionId(0x1000), FunctionId(0x2000))],
        "labelling the evidence as weak must not silently drop the pair"
    );
}
