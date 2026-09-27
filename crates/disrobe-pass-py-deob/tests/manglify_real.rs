#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::manglify::ManglifyPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[(&str, Quality)] = &[
    ("edge_cases_3_8", Quality::Partial),
    ("edge_hello_world", Quality::Full),
    ("edge_async_fn", Quality::Full),
    ("edge_lambda_in_listcomp", Quality::Full),
    ("edge_typing_generic", Quality::Full),
    ("edge_walrus_operator", Quality::Full),
];

#[test]
fn manglify_real_fixtures_detect_and_peel() {
    for (slot, expected_quality) in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture("manglify", slot);
        let det: DetectReport = ManglifyPass.detect(&fixture);
        assert!(det.matched, "manglify slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = ManglifyPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("manglify slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality, *expected_quality,
            "manglify slot {slot}: quality moved; diagnostics={:?}",
            peel.diagnostics
        );
        if matches!(peel.quality, Quality::Full) {
            let original: String = String::from_utf8_lossy(&fixture).into_owned();
            assert!(
                original.contains("class Engine") && original.contains("def Combustion"),
                "manglify slot {slot}: real upstream fixture must carry the Engine loader trailer"
            );
            assert!(
                !peel.recovered_source.contains("class Engine")
                    && !peel.recovered_source.contains("def Combustion"),
                "manglify slot {slot}: Quality::Full must strip the Engine/Combustion loader trailer, but it survived in the recovered source"
            );
            let bindings: usize = peel
                .diagnostics
                .get("ast_bindings_learned")
                .and_then(|v: &String| v.parse::<usize>().ok())
                .unwrap_or(0);
            assert!(
                bindings > 0,
                "manglify slot {slot}: Quality::Full must reflect real AST binding recovery, got ast_bindings_learned={bindings}; diagnostics={:?}",
                peel.diagnostics
            );
        }
    }
}
