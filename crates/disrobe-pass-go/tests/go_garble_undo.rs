#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{GarbleQuality, GoAnalysis, analyze};

#[test]
fn garble_detected_on_garble_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GARBLE);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze garbled");
    assert!(
        !matches!(analysis.garble.quality, GarbleQuality::None),
        "garble heuristics should fire on garble-built binary; got {:?}",
        analysis.garble.quality
    );
    assert!(analysis.garble.detection_score >= 1);
    assert!(
        analysis.garble.name_recovery_wall.is_some(),
        "seedless garble build must document the name-recovery wall"
    );
    assert!(
        !analysis.garble.seed_recoverable,
        "no seed is embedded in a trimpath garble build"
    );
}

#[test]
fn garble_name_recovery_measured_against_fixture() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GARBLE);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze garbled");
    let stats: disrobe_pass_go::NameRecoveryStats = analysis.garble.name_recovery;
    assert!(
        stats.total_funcs > 100,
        "garble keeps stdlib funcs in pclntab; got {}",
        stats.total_funcs
    );
    #[allow(clippy::cast_precision_loss)]
    let stdlib_ratio: f64 = stats.stdlib_recovered as f64 / stats.total_funcs as f64;
    assert!(
        stdlib_ratio >= 0.50,
        "stdlib names survive garble and must be recovered via pclntab; got {:.3} ({} of {})",
        stdlib_ratio,
        stats.stdlib_recovered,
        stats.total_funcs
    );
    assert!(
        stats.user_hashed_erased >= 1,
        "garble must show at least one cryptographically-hashed user name (the recovery wall)"
    );
    let limit: &str = analysis
        .garble
        .literal_recovery_limit
        .as_deref()
        .expect("garble build must document how -literals strings are handled");
    let lowered: String = limit.to_ascii_lowercase();
    assert!(
        lowered.contains("not a one-time pad") || lowered.contains("not an information-theoretic"),
        "the -literals limit must be honestly reclassified away from the false one-time-pad claim; \
         got: {limit}"
    );
    assert!(
        lowered.contains("emulat")
            && (lowered.contains("init") || lowered.contains("decrypt thunk")),
        "the limit must state the keys are init/thunk-derived and recovered by emulation; got: {limit}"
    );
    assert!(
        !lowered.contains("one-time-pad with no statically recoverable key"),
        "the retired one-time-pad wall phrasing must not reappear"
    );
}

#[test]
fn garble_none_on_normal_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(matches!(
        analysis.garble.quality,
        GarbleQuality::None | GarbleQuality::Detected
    ));
}
