#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GarbleQuality, GoAnalysis, analyze};

#[test]
fn garble_detected_on_garble_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_GARBLE) else {
        return;
    };
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
fn garble_none_on_normal_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(matches!(
        analysis.garble.quality,
        GarbleQuality::None | GarbleQuality::Detected
    ));
}
