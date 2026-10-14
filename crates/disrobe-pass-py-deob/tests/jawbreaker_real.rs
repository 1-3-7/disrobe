#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::obfuscators::jawbreaker::JawbreakerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};
use disrobe_pass_py_deob::{
    AutoDeobOutcome, ObfuscatorPass, ObfuscatorPeelSummary, PeelResult, RouteKind, WallReason,
    auto_deobfuscate, peel,
};

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

#[test]
fn jawbreaker_real_fixtures_are_detect_only_remote_loader() {
    for slot in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture("jawbreaker", slot);
        let det: DetectReport = JawbreakerPass.detect(&fixture);
        assert!(det.matched, "jawbreaker slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = JawbreakerPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("jawbreaker slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::DetectOnly,
            "jawbreaker slot {slot}: remote-fetch loader must be DetectOnly, got {:?}",
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
}

#[test]
fn product_peel_reports_jawbreaker_as_a_refused_remote_payload() {
    for slot in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture("jawbreaker", slot);
        let result: PeelResult =
            peel(&fixture).unwrap_or_else(|e| panic!("jawbreaker slot {slot} peel: {e:?}"));
        assert!(
            !result.recovered,
            "jawbreaker slot {slot}: nothing is recovered"
        );
        assert_eq!(result.wall, Some(WallReason::RemotePayload), "{slot}");
        let summary: &ObfuscatorPeelSummary = result
            .obfuscator
            .as_ref()
            .unwrap_or_else(|| panic!("jawbreaker slot {slot} must name the obfuscator"));
        assert_eq!(summary.obfuscator, Obfuscator::Jawbreaker, "{slot}");
        assert_eq!(summary.quality, Quality::DetectOnly, "{slot}");
        assert!(
            summary
                .lossy_notes
                .iter()
                .any(|note: &String| note.contains("refused (remote payload)")),
            "jawbreaker slot {slot}: the report must name the refusal: {:?}",
            summary.lossy_notes
        );
        assert_eq!(result.final_source.as_bytes(), fixture.as_slice(), "{slot}");
        let routed: AutoDeobOutcome = auto_deobfuscate(&fixture, None);
        assert_eq!(routed.kind, RouteKind::Unidentified, "{slot}");
        assert!(routed.source.is_none(), "{slot}");
        assert!(
            routed
                .guidance
                .as_deref()
                .is_some_and(|guidance: &str| guidance
                    .starts_with("Jawbreaker detected; recovery refused (RemotePayload)")),
            "{slot}: {:?}",
            routed.guidance
        );
    }
}
