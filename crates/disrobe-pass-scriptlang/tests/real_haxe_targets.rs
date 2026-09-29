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

#[test]
fn haxe_ceiling_is_route_only_for_every_real_emitted_target() {
    let js: HaxeFingerprint = detect(HAXE_JS).expect("js");
    assert_eq!(
        js.route_pass_id, "js.deob",
        "the haxe ceiling is to route the emitted js to the js deobfuscator, not reimplement it"
    );
    let swf: HaxeFingerprint = detect(HAXE_SWF).expect("swf");
    assert_eq!(
        swf.route_pass_id, "as3.classify",
        "emitted swf carries only a fingerprint; route to the as3 pass"
    );
    let hl: HaxeFingerprint = detect(HAXE_HL).expect("hl");
    assert_eq!(
        hl.route_pass_id, "scriptlang.classify",
        "hashlink is haxe's own vm bytecode with no downstream pass; it stays fingerprint-only here"
    );
}

#[test]
fn haxe_fingerprint_is_metadata_only_no_source_recovery() {
    let art: ScriptArtifact = analyze(HAXE_JS).expect("analyze");
    let ScriptArtifact::Haxe(fp): ScriptArtifact = art else {
        panic!("expected a Haxe artifact, got {art:?}");
    };
    assert!(
        fp.haxe_confirmed,
        "the haxe artifact is purely a fingerprint: target + route + version, with no recovered \
         source symbols; the cross-target ceiling means recovery happens in the routed-to pass"
    );
    assert_eq!(fp.target, HaxeTarget::JavaScript);
    assert_eq!(fp.route_pass_id, "js.deob");
}
