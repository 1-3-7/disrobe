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
fn legal_stance_requires_authorization() {
    assert_eq!(PACE_LEGAL, LegalStance::AmberDetectOnly);
    assert_eq!(PACE_LEGAL, PACE_FAMILY.legal_stance());
    assert!(PACE_LEGAL.allows_bypass_with_authorization());
}

#[test]
fn detect_finds_synthesized_pace() {
    let det: ProtectorDetection = detect(SYNTHESIZED_PACE).expect("detection");
    assert_eq!(det.family, PACE_FAMILY);
    assert_eq!(det.legal_stance, LegalStance::AmberDetectOnly);
    assert_eq!(det.stance_doc, "docs/legal/pace-js-stance.md");
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
fn strip_requires_authorization() {
    let err: Error = deob(SYNTHESIZED_PACE, &ProtectorOptions::default()).unwrap_err();
    assert!(matches!(err, Error::AuthorizationRequired { .. }));
}

#[test]
fn authorized_strip_removes_static_guards_and_preserves_program() {
    let opts: ProtectorOptions = ProtectorOptions {
        i_have_authorization: true,
    };
    let out: ProtectorOutput = deob(SYNTHESIZED_PACE, &opts).expect("pace strip");
    assert_eq!(out.family, PACE_FAMILY);
    assert_eq!(out.legal_stance, LegalStance::AmberDetectOnly);
    assert_eq!(out.stance_doc, "docs/legal/pace-js-stance.md");
    assert!(out.source.contains("function realWork"));
    assert!(out.source.contains("unrelated business logic"));
    assert!(!out.source.contains("setInterval"));
    assert!(!out.source.contains("location.reload"));
    assert!(!out.source.contains("__PACE__"));
    assert!(!out.source.contains("_PACE_FUSION_"));
    assert!(out.stats.reversed >= 4usize);
}

#[test]
fn detect_only_report_returns_unstripped_telemetry() {
    let out: ProtectorOutput = detect_only_report(SYNTHESIZED_PACE);
    assert_eq!(out.family, PACE_FAMILY);
    assert_eq!(out.legal_stance, LegalStance::AmberDetectOnly);
    assert_eq!(out.stance_doc, "docs/legal/pace-js-stance.md");
    assert!(out.detection.is_some());
    assert_eq!(out.stats.reversed, 0);
    assert!(
        out.stats
            .errors
            .iter()
            .any(|e: &String| e.contains("DR-JS-PACE-UnsupportedPattern"))
    );
    assert_eq!(out.source, SYNTHESIZED_PACE);
}
