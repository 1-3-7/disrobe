#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes
)]

use disrobe_pass_js_deob::{
    ARXAN_FAMILY, ARXAN_LEGAL, Error, LegalStance, ProtectorDetection, ProtectorOptions,
    ProtectorOutput, arxan_deobfuscate as deob, detect_arxan as detect,
};

const SYNTHESIZED_ARXAN: &str = r#"/* (c) Digital.ai Application Protection - synthesized fixture, mimics CVE-2024 public disclosure */
function __guard_abc123def() {
  var k = atob('Q2hlY2tzdW1HdWFyZFRva2VuQUFBQQ==');
  return k.length;
}
var data = [1, 2, 3, 4, 5];
for (var __chk = 0; __chk < data.length; __chk++) { data[__chk] ^= 0x42; }
if (__arxan_integrity() !== 0xdeadbeef) { throw new Error('tamper'); }
function realWork() { return 42; }
"#;

#[test]
fn legal_stance_is_amber_detect_only() {
    assert_eq!(ARXAN_LEGAL, LegalStance::AmberDetectOnly);
    assert_eq!(ARXAN_LEGAL, ARXAN_FAMILY.legal_stance());
    assert!(ARXAN_LEGAL.allows_bypass_with_authorization());
    assert_eq!(
        ARXAN_LEGAL.stance_doc(),
        "docs/legal/digital-ai-arxan-stance.md"
    );
}

#[test]
fn detect_finds_synthesized_arxan() {
    let det: ProtectorDetection = detect(SYNTHESIZED_ARXAN).expect("detection");
    assert_eq!(det.family, ARXAN_FAMILY);
    assert_eq!(det.legal_stance, LegalStance::AmberDetectOnly);
    assert!(det.confidence >= 0.30, "confidence = {}", det.confidence);
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m.contains("digital-ai") || m.contains("guard"))
    );
}

#[test]
fn detect_returns_none_for_clean_js() {
    let src: &str = "function multiply(a, b) { return a * b; }";
    assert!(detect(src).is_none());
}

#[test]
fn strip_requires_authorization() {
    let err: Error = deob(SYNTHESIZED_ARXAN, &ProtectorOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        Error::AuthorizationRequired { transform: "arxan" }
    ));
}

#[test]
fn strip_removes_only_publicly_documented_patterns() {
    let opts: ProtectorOptions = ProtectorOptions {
        i_have_authorization: true,
    };
    let out: ProtectorOutput = deob(SYNTHESIZED_ARXAN, &opts).expect("deob");
    assert_eq!(out.family, ARXAN_FAMILY);
    assert_eq!(out.legal_stance, LegalStance::AmberDetectOnly);
    assert_eq!(out.stance_doc, "docs/legal/digital-ai-arxan-stance.md");
    assert!(out.detection.is_some());
    assert!(!out.source.contains("__arxan_integrity"));
    assert!(out.source.contains("realWork"));
    assert!(out.stats.reversed >= 1);
}
