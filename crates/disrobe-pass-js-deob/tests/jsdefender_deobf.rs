#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes
)]

use disrobe_pass_js_deob::{
    Error, JSDEFENDER_FAMILY, JSDEFENDER_LEGAL, LegalStance, ProtectorDetection, ProtectorOptions,
    ProtectorOutput, StringArrayRecovery, detect_jsdefender as detect,
    jsdefender_deobfuscate as deob, recover_string_array,
};

const REAL_OBFUSCATOR_IO: &str =
    include_str!("../../../corpus/js/javascript-obfuscator/obfuscated.js");
const CLEAN_SOURCE: &str = include_str!("../../../corpus/js/javascript-obfuscator/hello.js");

const STRING_ARRAY_LITERALS: &[&str] = &["hello ", "world", "log"];

const SURVIVING_IDENTIFIERS: &[&str] = &["greet", "console"];

const SYNTHESIZED_JSDEFENDER_MARKERS: &str = r#"/* PreEmptive Solutions JSDefender (detector-signature smoke fixture; NOT a recovery oracle) */
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

const fn authorized() -> ProtectorOptions {
    ProtectorOptions {
        i_have_authorization: true,
    }
}

#[test]
fn clean_source_defines_the_independent_token_oracle() {
    for tok in STRING_ARRAY_LITERALS.iter().chain(SURVIVING_IDENTIFIERS) {
        assert!(
            CLEAN_SOURCE.contains(tok),
            "oracle token {:?} must originate from the independent clean source",
            tok
        );
    }
}

#[test]
fn real_obfuscator_io_fixture_hides_the_clean_string_literals() {
    for tok in STRING_ARRAY_LITERALS {
        assert!(
            !REAL_OBFUSCATOR_IO.contains(tok),
            "fixture must be genuinely obfuscated: string literal {:?} must be string-array-encoded, \
             not present verbatim in the real tool output",
            tok
        );
    }
}

#[test]
fn differential_vs_source_recovers_string_array_tokens() {
    let opts: ProtectorOptions = authorized();
    let out: ProtectorOutput = deob(REAL_OBFUSCATOR_IO, &opts).expect("deob");

    assert_eq!(out.family, JSDEFENDER_FAMILY);
    assert!(
        out.bytes_out < out.bytes_in,
        "recovery must shrink the obfuscated input (in={} out={})",
        out.bytes_in,
        out.bytes_out
    );
    assert!(
        out.stats.reversed > 0,
        "recovery must reverse at least one call site, got {:?}",
        out.stats
    );

    for tok in STRING_ARRAY_LITERALS {
        assert!(
            out.source.contains(tok),
            "DifferentialVsSource: recovered output must surface clean string literal {:?}; got:\n{}",
            tok,
            out.source
        );
    }
    for tok in SURVIVING_IDENTIFIERS {
        assert!(
            out.source.contains(tok),
            "DifferentialVsSource: recovered output must preserve clean identifier {:?}",
            tok
        );
    }
}

#[test]
fn differential_vs_source_via_string_array_engine() {
    let recovery: StringArrayRecovery = recover_string_array(REAL_OBFUSCATOR_IO)
        .expect("recovery should not error")
        .expect("real obfuscator.io fixture must carry a recoverable string array");

    assert_eq!(recovery.array_id, "a0_0x292a");
    assert!(recovery.rotator_removed, "the rotator IIFE must be removed");
    assert!(
        recovery.call_sites_inlined > 0,
        "at least one decoder call site must inline; got {:?}",
        recovery
    );

    for tok in STRING_ARRAY_LITERALS {
        assert!(
            recovery.rewritten_source.contains(tok),
            "string-array recovery must inline clean string literal {:?}",
            tok
        );
    }
}

#[test]
fn falsification_wrong_recovery_token_is_rejected() {
    let opts: ProtectorOptions = authorized();
    let out: ProtectorOutput = deob(REAL_OBFUSCATOR_IO, &opts).expect("deob");

    let fabricated: &str = "this_token_is_not_in_the_clean_source";
    assert!(
        !CLEAN_SOURCE.contains(fabricated),
        "guard: the falsification token must be absent from the clean oracle"
    );
    assert!(
        !out.source.contains(fabricated),
        "falsification: recovery must not invent tokens the clean source never contained"
    );
}

#[test]
fn falsification_unrecovered_input_fails_the_oracle() {
    let still_obfuscated: &str = REAL_OBFUSCATOR_IO;
    let any_clean_literal_present: bool = STRING_ARRAY_LITERALS
        .iter()
        .any(|t: &&str| still_obfuscated.contains(t));
    assert!(
        !any_clean_literal_present,
        "falsification control: the string-array literals must be absent from the raw obfuscated input - \
         this proves the differential oracle measures recovery, not the fixture itself"
    );
}

#[test]
fn legal_stance_is_amber_leaning_green() {
    assert_eq!(JSDEFENDER_LEGAL, LegalStance::AmberLeaningGreen);
    assert_eq!(JSDEFENDER_LEGAL, JSDEFENDER_FAMILY.legal_stance());
    assert!(JSDEFENDER_LEGAL.allows_bypass_with_authorization());
    assert_eq!(
        JSDEFENDER_FAMILY.stance_doc(),
        "docs/legal/jsdefender-stance.md"
    );
}

#[test]
fn deobfuscate_requires_authorization() {
    let err: Error = deob(REAL_OBFUSCATOR_IO, &ProtectorOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        Error::AuthorizationRequired {
            transform: "jsdefender"
        }
    ));
}

#[test]
fn detector_signature_smoke_matches_synthesized_markers() {
    let det: ProtectorDetection =
        detect(SYNTHESIZED_JSDEFENDER_MARKERS).expect("synthesized marker fixture must detect");
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
fn detector_returns_none_for_clean_js() {
    let src: &str = "function add(a, b) { return a + b; }\nconst x = 1;";
    assert!(detect(src).is_none());
}

#[test]
fn detector_does_not_misfire_on_unrelated_obfuscator() {
    assert!(
        detect(REAL_OBFUSCATOR_IO).is_none(),
        "JSDefender detector must not claim obfuscator.io output as PreEmptive JSDefender"
    );
}
