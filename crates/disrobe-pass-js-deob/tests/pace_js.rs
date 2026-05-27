#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes
)]

use disrobe_pass_js_deob::{
    Error, LegalStance, PACE_FAMILY, PACE_LEGAL, ProtectorDetection, ProtectorOptions,
    ProtectorOutput, detect_pace as detect, pace_deobfuscate as deob,
    pace_detect_only_report as detect_only_report,
};

const SYNTHESIZED_PACE: &str = r#"/* PACE Anti-Piracy Fusion (synthesized fixture, mimics public PACE documentation) */
if (window['__PACE__'] === undefined) { location.reload(); }
setInterval(function () { if (!__PACE__.alive()) { __PACE__.kill(); } }, 5000);
var ilok_token = 'redacted-ilok-bind-id';
function realWork() { return 'unrelated business logic'; }
"#;

#[test]
fn legal_stance_is_amber_detect_no_bypass() {
    assert_eq!(PACE_LEGAL, LegalStance::AmberDetectNoBypass);
    assert_eq!(PACE_LEGAL, PACE_FAMILY.legal_stance());
    assert!(!PACE_LEGAL.allows_bypass_with_authorization());
    assert_eq!(PACE_LEGAL.stance_doc(), "docs/legal/pace-js-stance.md");
}

#[test]
fn detect_finds_synthesized_pace() {
    let det: ProtectorDetection = detect(SYNTHESIZED_PACE).expect("detection");
    assert_eq!(det.family, PACE_FAMILY);
    assert_eq!(det.legal_stance, LegalStance::AmberDetectNoBypass);
    assert!(det.confidence >= 0.30, "confidence = {}", det.confidence);
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m.contains("pace") || m.contains("ilok"))
    );
}

#[test]
fn detect_returns_none_for_clean_js() {
    let src: &str = "function compute() { return 1 + 2; }";
    assert!(detect(src).is_none());
}

#[test]
fn bypass_rejected_without_authorization() {
    let err: Error = deob(SYNTHESIZED_PACE, &ProtectorOptions::default()).unwrap_err();
    match err {
        Error::PaceBypassUnsupported { stance_doc } => {
            assert_eq!(stance_doc, "docs/legal/pace-js-stance.md");
        }
        other => panic!("expected PaceBypassUnsupported, got {other:?}"),
    }
}

#[test]
fn bypass_rejected_even_with_authorization() {
    let opts: ProtectorOptions = ProtectorOptions {
        i_have_authorization: true,
    };
    let err: Error = deob(SYNTHESIZED_PACE, &opts).unwrap_err();
    match err {
        Error::PaceBypassUnsupported { stance_doc } => {
            assert_eq!(stance_doc, "docs/legal/pace-js-stance.md");
        }
        other => panic!("expected PaceBypassUnsupported, got {other:?}"),
    }
}

#[test]
fn detect_only_report_returns_detect_only_marker() {
    let out: ProtectorOutput = detect_only_report(SYNTHESIZED_PACE);
    assert_eq!(out.family, PACE_FAMILY);
    assert_eq!(out.legal_stance, LegalStance::AmberDetectNoBypass);
    assert_eq!(out.stance_doc, "docs/legal/pace-js-stance.md");
    assert!(out.detection.is_some());
    assert_eq!(out.stats.reversed, 0);
    assert!(
        out.stats
            .errors
            .iter()
            .any(|e: &String| e.contains("DR-JS-PACE-DetectOnly"))
    );
    assert_eq!(out.source, SYNTHESIZED_PACE);
}
