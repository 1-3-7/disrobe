#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_scriptlang::lang::haxe::{
    HaxeCrossRoute, HaxeCrossTarget, HaxeFingerprint, HaxeTarget, detect, route_cross_target,
};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const HAXE_JS: &[u8] = include_bytes!("fixtures/haxe_main.js");
const HAXE_SWF: &[u8] = include_bytes!("fixtures/haxe_main.swf");
const HAXE_HL: &[u8] = include_bytes!("fixtures/haxe_main.hl");
const HAXE_HXCPP: &[u8] = include_bytes!("fixtures/Main.hxcpp.cpp");

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

fn jvm_class_stub(major: u16) -> Vec<u8> {
    let mut v: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe];
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&major.to_be_bytes());
    v.extend_from_slice(&[0u8; 8]);
    v
}

fn dotnet_pe_stub() -> Vec<u8> {
    let lfanew: usize = 0x80usize;
    let opt_magic_pos: usize = lfanew + 0x18;
    let dir_table: usize = opt_magic_pos + 0x60;
    let clr_entry: usize = dir_table + 14 * 8;
    let mut v: Vec<u8> = vec![0u8; clr_entry + 8];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
    v[lfanew..lfanew + 4].copy_from_slice(b"PE\x00\x00");
    v[opt_magic_pos..opt_magic_pos + 2].copy_from_slice(&0x10b_u16.to_le_bytes());
    v[clr_entry..clr_entry + 4].copy_from_slice(&0x2000_u32.to_le_bytes());
    v[clr_entry + 4..clr_entry + 8].copy_from_slice(&0x48_u32.to_le_bytes());
    v
}

#[test]
fn haxe_jvm_target_routes_to_jvm_pass() {
    let class: Vec<u8> = jvm_class_stub(52);
    let route: HaxeCrossRoute = route_cross_target(&class).expect("jvm route");
    assert_eq!(route.target, HaxeCrossTarget::JvmClassfile);
    assert_eq!(
        route.route_pass_id, "jvm.classify",
        "haxe -java classfile output must dispatch to the jvm pass entry point"
    );
}

#[test]
fn haxe_dotnet_target_routes_to_dotnet_pass() {
    let pe: Vec<u8> = dotnet_pe_stub();
    let route: HaxeCrossRoute = route_cross_target(&pe).expect("dotnet route");
    assert_eq!(route.target, HaxeCrossTarget::DotNetCil);
    assert_eq!(
        route.route_pass_id, "dotnet.classify",
        "haxe -cs PE+CLR output must dispatch to the dotnet pass entry point"
    );
}

#[test]
fn real_haxe_hxcpp_target_routes_to_native_oracle() {
    let route: HaxeCrossRoute = route_cross_target(HAXE_HXCPP).expect("hxcpp route");
    assert_eq!(route.target, HaxeCrossTarget::Hxcpp);
    assert_eq!(
        route.route_pass_id, "disrobe-pass-native",
        "haxe hxcpp/c++ output must dispatch to the native pass"
    );
    assert!(
        route.haxe_marker_present,
        "hxcpp emission carries the hx:: marker derived from Main.hx"
    );
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
fn haxe_cross_target_routing_matrix_is_exhaustive_and_stable() {
    let jvm: HaxeCrossRoute = route_cross_target(&jvm_class_stub(52)).expect("jvm classfile route");
    assert_eq!(
        (jvm.target, jvm.route_pass_id),
        (HaxeCrossTarget::JvmClassfile, "jvm.classify")
    );
    let cs: HaxeCrossRoute = route_cross_target(&dotnet_pe_stub()).expect("dotnet route");
    assert_eq!(
        (cs.target, cs.route_pass_id),
        (HaxeCrossTarget::DotNetCil, "dotnet.classify")
    );
    let cpp: HaxeCrossRoute = route_cross_target(HAXE_HXCPP).expect("hxcpp route");
    assert_eq!(
        (cpp.target, cpp.route_pass_id),
        (HaxeCrossTarget::Hxcpp, "disrobe-pass-native")
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
