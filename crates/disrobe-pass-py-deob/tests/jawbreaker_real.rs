#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::jawbreaker::JawbreakerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_8",
    "edge_hello_world",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_walrus_operator",
    "edge_match_statement",
    "edge_structural_pattern",
    "edge_typing_generic",
];

/// Decodes Jawbreaker's triple-encode to prove the remote-loader shape as `DetectOnly` (no source is embedded).
#[test]
fn jawbreaker_real_fixtures_are_honest_detect_only_remote_loader() {
    let mut tested: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("jawbreaker", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = JawbreakerPass.detect(&fixture);
        assert!(det.matched, "jawbreaker slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = JawbreakerPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("jawbreaker slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::DetectOnly,
            "jawbreaker slot {slot}: remote-fetch loader must be honest DetectOnly, got {:?}",
            peel.quality
        );
        assert!(
            peel.recovered_source.is_empty(),
            "jawbreaker slot {slot}: DetectOnly must not emit a fake recovered source"
        );
        assert_eq!(
            peel.diagnostics.get("remote_loader").map(String::as_str),
            Some("true"),
            "jawbreaker slot {slot}: must statically confirm the urllib remote loader; diagnostics={:?}",
            peel.diagnostics
        );
        assert!(
            peel.stages_applied.iter().any(|s: &String| s == "base16")
                && peel.stages_applied.iter().any(|s: &String| s == "base32")
                && peel.stages_applied.iter().any(|s: &String| s == "base64"),
            "jawbreaker slot {slot}: triple-encode must be peeled to expose the loader, got {:?}",
            peel.stages_applied
        );
    }
    if tested == 0 {
        common::skip_absent_corpus(
            "jawbreaker_real_fixtures_are_honest_detect_only_remote_loader",
            "jawbreaker",
        );
        return;
    }
    assert!(
        tested >= 10,
        "expected 10+ jawbreaker real fixtures, got {tested}"
    );
}
