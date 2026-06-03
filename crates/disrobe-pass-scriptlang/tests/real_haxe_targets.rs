#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_scriptlang::lang::haxe::{HaxeFingerprint, HaxeTarget, detect};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const HAXE_JS: &[u8] = include_bytes!("fixtures/haxe_main.js");
const HAXE_SWF: &[u8] = include_bytes!("fixtures/haxe_main.swf");
const HAXE_HL: &[u8] = include_bytes!("fixtures/haxe_main.hl");

#[test]
fn real_haxe_js_detects_and_routes() {
    let fp: HaxeFingerprint = detect(HAXE_JS).expect("haxe js detect");
    assert_eq!(fp.target, HaxeTarget::JavaScript);
    assert_eq!(fp.route_pass_id, "js.deob");
    assert!(fp.haxe_confirmed);
    assert_eq!(fp.compiler_version.as_deref(), Some("4.3.6"));
    assert_eq!(classify(HAXE_JS), Some(ScriptLang::Haxe));
}

#[test]
fn real_haxe_swf_detects_and_routes_to_as3() {
    let fp: HaxeFingerprint = detect(HAXE_SWF).expect("haxe swf detect");
    assert_eq!(fp.target, HaxeTarget::SwfFlash);
    assert_eq!(fp.route_pass_id, "as3.classify");
    assert_eq!(classify(HAXE_SWF), Some(ScriptLang::Haxe));
}

#[test]
fn real_haxe_hl_detects_hashlink() {
    let fp: HaxeFingerprint = detect(HAXE_HL).expect("haxe hl detect");
    assert_eq!(fp.target, HaxeTarget::HashLink);
    assert!(fp.hl_version.is_some());
    assert_eq!(classify(HAXE_HL), Some(ScriptLang::Haxe));
}

#[test]
fn real_haxe_analyze_returns_haxe_artifact() {
    for bytes in [HAXE_JS, HAXE_SWF, HAXE_HL] {
        let art: ScriptArtifact = analyze(bytes).expect("analyze");
        match art {
            ScriptArtifact::Haxe(_) => {}
            other => panic!("expected Haxe artifact, got {other:?}"),
        }
    }
}
