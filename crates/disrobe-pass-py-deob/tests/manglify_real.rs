#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::manglify::ManglifyPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_8",
    "edge_hello_world",
    "edge_async_fn",
    "edge_lambda_in_listcomp",
    "edge_typing_generic",
    "edge_walrus_operator",
];

#[test]
fn manglify_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    let mut full_count: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("manglify", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = ManglifyPass.detect(&fixture);
        assert!(det.matched, "manglify slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = ManglifyPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("manglify slot {slot} peel: {e:?}"));
        if matches!(peel.quality, Quality::Full) {
            full_count += 1;
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
    if tested == 0 {
        common::skip_absent_corpus("manglify_real_fixtures_detect_and_peel", "manglify");
        return;
    }
    assert!(
        full_count >= 1,
        "expected at least one manglify fixture to upgrade to Quality::Full via AST eval, got {full_count}"
    );
}
