#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes
)]

use disrobe_pass_js_deob::{
    Error, JSDEFENDER_FAMILY, JSDEFENDER_LEGAL, LegalStance, ProtectorDetection, ProtectorOptions,
    ProtectorOutput, detect_jsdefender as detect, jsdefender_deobfuscate as deob,
};

const SYNTHESIZED_JSDEFENDER: &str = r#"/* PreEmptive Solutions JSDefender (synthesized fixture, mimics published preset) */
var _PreEmptive_strs = ['hello', 'world', 'foo', 'bar', 'baz'];
function _PreEmptive_decode(i) { return _PreEmptive_strs[i]; }
var state = 0;
while (state !== 3) {
  switch (state) {
    case 0:
      var a = _PreEmptive_decode(0);
      state = 1;
      break;
    case 1:
      var b = _PreEmptive_decode(1);
      state = 2;
      break;
    case 2:
      console.log(a + ' ' + b);
      state = 3;
      break;
  }
}
if (!![]) { console.log('alive'); }
if (![]) { console.log('dead unreachable'); }
"#;

#[test]
fn legal_stance_is_amber_leaning_green() {
    assert_eq!(JSDEFENDER_LEGAL, LegalStance::AmberLeaningGreen);
    assert_eq!(JSDEFENDER_LEGAL, JSDEFENDER_FAMILY.legal_stance());
    assert!(JSDEFENDER_LEGAL.allows_bypass_with_authorization());
    assert_eq!(
        JSDEFENDER_LEGAL.stance_doc(),
        "docs/legal/jsdefender-stance.md"
    );
}

#[test]
fn detect_finds_synthesized_jsdefender() {
    let det: ProtectorDetection = detect(SYNTHESIZED_JSDEFENDER).expect("detection");
    assert_eq!(det.family, JSDEFENDER_FAMILY);
    assert_eq!(det.legal_stance, LegalStance::AmberLeaningGreen);
    assert!(det.confidence >= 0.30, "confidence = {}", det.confidence);
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m.contains("preemptive"))
    );
}

#[test]
fn detect_returns_none_for_clean_js() {
    let src: &str = "function add(a, b) { return a + b; }\nconst x = 1;";
    assert!(detect(src).is_none());
}

#[test]
fn deobfuscate_requires_authorization() {
    let err: Error = deob(SYNTHESIZED_JSDEFENDER, &ProtectorOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        Error::AuthorizationRequired {
            transform: "jsdefender"
        }
    ));
}

#[test]
fn deobfuscate_runs_full_peel_with_authorization() {
    let opts: ProtectorOptions = ProtectorOptions {
        i_have_authorization: true,
    };
    let out: ProtectorOutput = deob(SYNTHESIZED_JSDEFENDER, &opts).expect("deob");
    assert_eq!(out.family, JSDEFENDER_FAMILY);
    assert_eq!(out.legal_stance, LegalStance::AmberLeaningGreen);
    assert_eq!(out.stance_doc, "docs/legal/jsdefender-stance.md");
    assert!(out.detection.is_some());
    assert_eq!(out.bytes_in, SYNTHESIZED_JSDEFENDER.len());
    assert_eq!(out.bytes_out, out.source.len());
}
