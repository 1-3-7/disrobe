#![cfg(feature = "chain")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes
)]

use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, Pass,
};
use disrobe_core::error::CoreError;
use disrobe_core::pass::PassContext;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_js_deob::chain_detector::{JS_OBF_PASS, JsObfDetector, PASS_ID};

const JSDEFENDER_FIXTURE: &str =
    include_str!("../../../corpus/js/protectors/jsdefender/edge_cases_obf.synth.js");
const ARXAN_FIXTURE: &str =
    include_str!("../../../corpus/js/protectors/arxan/edge_cases_guarded.synth.js");
const PACE_FIXTURE: &str =
    include_str!("../../../corpus/js/protectors/pace/edge_cases_paced.synth.js");

const fn ctx(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

fn artifact_from(bytes: &[u8]) -> Artifact {
    Artifact::new(Rung::Raw, bytes.to_vec(), [0_u8; 32])
}

const fn asserted() -> PassContext<'static> {
    PassContext {
        path_hint: None,
        i_have_authorization: true,
    }
}

fn run_asserted(fixture: &str) -> Artifact {
    JS_OBF_PASS
        .run_with_context(&artifact_from(fixture.as_bytes()), asserted())
        .expect("an asserted-authorization chain run must peel the protector")
}

fn withheld_failure(fixture: &str) -> String {
    let err: CoreError = JS_OBF_PASS
        .run_with_context(&artifact_from(fixture.as_bytes()), PassContext::default())
        .expect_err("a chain run without the operator's assertion must refuse the gated peel");
    format!("{err}")
}

#[test]
fn detector_emits_pace_verdict_with_stance_metadata() {
    let bytes: &[u8] = PACE_FIXTURE.as_bytes();
    let v: DetectVerdict = JsObfDetector
        .detect(&ctx(bytes))
        .expect("pace fixture must trigger a verdict");
    assert_eq!(v.pass_id, PASS_ID);
    assert_eq!(v.format_tag, "js-pace");
    assert_eq!(v.family, FAMILY_OBFUSCATOR_WRAPPER);
    assert!(v.explain.contains("pace js"), "explain={}", v.explain);
    assert!(
        v.explain.contains("docs/legal/pace-js-stance.md"),
        "explain should cite legal stance, got {}",
        v.explain,
    );
}

#[test]
fn detector_emits_jsdefender_verdict() {
    let bytes: &[u8] = JSDEFENDER_FIXTURE.as_bytes();
    let v: DetectVerdict = JsObfDetector
        .detect(&ctx(bytes))
        .expect("jsdefender fixture must trigger a verdict");
    assert_eq!(v.format_tag, "js-jsdefender");
    assert_eq!(v.family, FAMILY_OBFUSCATOR_WRAPPER);
    assert!(v.confidence > 0.0);
    assert!(
        v.explain.contains("docs/legal/jsdefender-stance.md"),
        "explain should cite legal stance, got {}",
        v.explain,
    );
}

#[test]
fn detector_emits_arxan_verdict() {
    let bytes: &[u8] = ARXAN_FIXTURE.as_bytes();
    let v: DetectVerdict = JsObfDetector
        .detect(&ctx(bytes))
        .expect("arxan fixture must trigger a verdict");
    assert_eq!(v.format_tag, "js-arxan");
    assert_eq!(v.family, FAMILY_OBFUSCATOR_WRAPPER);
    assert!(v.confidence > 0.0);
    assert!(
        v.explain.contains("docs/legal/digital-ai-arxan-stance.md"),
        "explain should cite legal stance, got {}",
        v.explain,
    );
}

#[test]
fn pace_runner_strips_static_guard_cfg() {
    let out: Artifact = run_asserted(PACE_FIXTURE);
    assert_eq!(out.rung, Rung::Surface);
    let body: &str =
        std::str::from_utf8(out.envelope.as_slice()).expect("pace artifact must be utf-8");
    assert!(
        body.contains("function realWork"),
        "business logic must survive"
    );
    assert!(
        !body.contains("setInterval"),
        "pace guard intervals must strip"
    );
    assert!(
        !body.contains("location.reload"),
        "presence check must strip"
    );
    assert!(!body.contains("__PACE__"), "runtime token must not survive");
}

#[test]
fn jsdefender_runner_emits_source_artifact() {
    let out: Artifact = run_asserted(JSDEFENDER_FIXTURE);
    assert_eq!(out.rung, Rung::Surface);
    let body: &str =
        std::str::from_utf8(out.envelope.as_slice()).expect("jsdefender artifact must be utf-8");
    assert!(body.contains("realWork"), "realWork must survive deob");
}

#[test]
fn arxan_runner_strips_publicly_documented_patterns() {
    let out: Artifact = run_asserted(ARXAN_FIXTURE);
    assert_eq!(out.rung, Rung::Surface);
    let body: &str =
        std::str::from_utf8(out.envelope.as_slice()).expect("arxan artifact must be utf-8");
    assert!(
        !body.contains("__arxan_integrity"),
        "integrity callout should be stripped"
    );
    assert!(
        !body.contains("__guard_"),
        "guard functions should be stripped"
    );
    assert!(!body.contains("__chk"), "checksum loops should be stripped");
    assert!(
        !body.contains("_ARXAN_"),
        "runtime marker should be stripped"
    );
    assert!(!body.contains("Digital.ai"), "banner should be stripped");
    assert!(body.contains("realWork"), "business logic must survive");
}

#[test]
fn detector_misses_clean_javascript() {
    let bytes: &[u8] = b"const x = 1;\nfunction add(a, b) { return a + b; }";
    assert!(JsObfDetector.detect(&ctx(bytes)).is_none());
}

#[test]
fn pace_peel_is_withheld_without_the_operator_assertion() {
    let message: String = withheld_failure(PACE_FIXTURE);
    assert!(message.contains("DR-JS-0920"), "message={message}");
    assert!(message.contains("PACE JS / Fusion"), "message={message}");
    assert!(
        message.contains("--i-have-authorization"),
        "message={message}"
    );
    assert!(
        message.contains("docs/legal/pace-js-stance.md"),
        "message={message}",
    );
}

#[test]
fn jsdefender_peel_is_withheld_without_the_operator_assertion() {
    let message: String = withheld_failure(JSDEFENDER_FIXTURE);
    assert!(message.contains("DR-JS-0920"), "message={message}");
    assert!(
        message.contains("PreEmptive JSDefender"),
        "message={message}"
    );
    assert!(
        message.contains("--i-have-authorization"),
        "message={message}"
    );
    assert!(
        message.contains("docs/legal/jsdefender-stance.md"),
        "message={message}",
    );
}

#[test]
fn arxan_peel_is_withheld_without_the_operator_assertion() {
    let message: String = withheld_failure(ARXAN_FIXTURE);
    assert!(message.contains("DR-JS-0920"), "message={message}");
    assert!(message.contains("Digital.ai Arxan"), "message={message}");
    assert!(
        message.contains("--i-have-authorization"),
        "message={message}"
    );
    assert!(
        message.contains("docs/legal/digital-ai-arxan-stance.md"),
        "message={message}",
    );
}

#[test]
fn the_context_free_entry_points_never_assert_authorization_for_the_operator() {
    for fixture in [PACE_FIXTURE, JSDEFENDER_FIXTURE, ARXAN_FIXTURE] {
        let art: Artifact = artifact_from(fixture.as_bytes());
        let plain: CoreError = JS_OBF_PASS
            .run(&art)
            .expect_err("the context-free run entry point carries no assertion");
        assert!(format!("{plain}").contains("DR-JS-0920"), "{plain}");
        let hinted: CoreError = JS_OBF_PASS
            .run_with_path(&art, Some("bundle.js"))
            .expect_err("a path hint alone is not an authorization assertion");
        assert!(format!("{hinted}").contains("DR-JS-0920"), "{hinted}");
    }
}

#[test]
fn detection_needs_no_authorization_while_the_peel_does() {
    let bytes: &[u8] = PACE_FIXTURE.as_bytes();
    let verdict: DetectVerdict = JsObfDetector
        .detect(&ctx(bytes))
        .expect("detection must not depend on the operator's assertion");
    assert_eq!(verdict.format_tag, "js-pace");
    assert!(
        PACE_FIXTURE.contains("__PACE__"),
        "the fixture must carry the runtime token for the peel comparison to mean anything",
    );
    assert!(withheld_failure(PACE_FIXTURE).contains("DR-JS-0920"));
    let peeled: Artifact = run_asserted(PACE_FIXTURE);
    let recovered: &str =
        std::str::from_utf8(peeled.envelope.as_slice()).expect("utf-8 recovered pace source");
    assert!(
        !recovered.contains("__PACE__"),
        "the asserted run is the only path that may strip the guard: {recovered}",
    );
}
