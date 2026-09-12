#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;

use std::path::PathBuf;

use disrobe_pass_dotnet::peel::static_decrypt::{StaticDecryptReport, recover_static_decoders};
use disrobe_pass_dotnet::peel::{
    PeelReport, PeelStrategy, peel_agile_net, peel_armdot, peel_babel_net, peel_by,
    peel_crypto_obfuscator, peel_deepsea, peel_dotfuscator, peel_dotnet_reactor, peel_eazfuscator,
    peel_goliath, peel_ilprotector, peel_maxtocode, peel_skater, peel_smartassembly,
    peel_spices_net, peel_themida_dotnet,
};
use disrobe_pass_dotnet::protectors::Protector;

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const HELLOAPP_CONFUSED_REL: &str = "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll";
const EDGECASES_CONFUSED_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn routing_dotnet_reactor_detects_and_routes_to_encrypted_resource_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Eziriz .NET Reactor");
    let report: PeelReport = peel_dotnet_reactor(&img).expect("peel");
    assert_eq!(report.protector, Protector::DotnetReactor);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(!report.notes.is_empty());
}

#[test]
fn routing_eazfuscator_detects_and_routes_to_encrypted_resource_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Eazfuscator.NET");
    let report: PeelReport = peel_eazfuscator(&img).expect("peel");
    assert_eq!(report.protector, Protector::EazfuscatorNet);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
}

#[test]
fn routing_smartassembly_detects_and_routes_to_encrypted_resource_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"PoweredByAttribute");
    let report: PeelReport = peel_smartassembly(&img).expect("peel");
    assert_eq!(report.protector, Protector::SmartAssembly);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
}

#[test]
fn routing_babel_net_detects_and_routes_to_encrypted_resource_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"BabelAttribute");
    let report: PeelReport = peel_babel_net(&img).expect("peel");
    assert_eq!(report.protector, Protector::BabelDotnet);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
}

#[test]
fn routing_deepsea_detects_and_routes_to_attribute_strip_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"DeepSeaObfuscator");
    let report: PeelReport = peel_deepsea(&img).expect("peel");
    assert_eq!(report.protector, Protector::DeepSea);
    assert_eq!(report.strategy, PeelStrategy::AttributeStripAndReport);
}

#[test]
fn routing_spices_net_detects_and_routes_to_attribute_strip_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"9rays.Net");
    let report: PeelReport = peel_spices_net(&img).expect("peel");
    assert_eq!(report.protector, Protector::SpicesNet);
    assert_eq!(report.strategy, PeelStrategy::AttributeStripAndReport);
}

#[test]
fn routing_skater_detects_and_routes_to_attribute_strip_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"RustemSoft.Skater");
    let report: PeelReport = peel_skater(&img).expect("peel");
    assert_eq!(report.protector, Protector::Skater);
    assert_eq!(report.strategy, PeelStrategy::AttributeStripAndReport);
}

#[test]
fn routing_dotfuscator_detects_and_routes_to_attribute_strip_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"DotfuscatorAttribute");
    let report: PeelReport = peel_dotfuscator(&img).expect("peel");
    assert_eq!(report.protector, Protector::Dotfuscator);
    assert_eq!(report.strategy, PeelStrategy::AttributeStripAndReport);
}

#[test]
fn routing_goliath_detects_and_routes_to_attribute_strip_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Goliath.NET");
    let report: PeelReport = peel_goliath(&img).expect("peel");
    assert_eq!(report.protector, Protector::Goliath);
    assert_eq!(report.strategy, PeelStrategy::AttributeStripAndReport);
}

#[test]
fn routing_crypto_obfuscator_detects_and_routes_to_encrypted_resource_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"CryptoObfuscator");
    let report: PeelReport = peel_crypto_obfuscator(&img).expect("peel");
    assert_eq!(report.protector, Protector::CryptoObfuscator);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
}

#[test]
fn routing_agile_net_detects_and_routes_to_encrypted_resource_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"AgileDotNet");
    let report: PeelReport = peel_agile_net(&img).expect("peel");
    assert_eq!(report.protector, Protector::AgileNet);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
}

#[test]
fn routing_armdot_detects_and_routes_to_detect_only_vm_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"ArmDot");
    let report: PeelReport = peel_armdot(&img).expect("peel");
    assert_eq!(report.protector, Protector::ArmDot);
    assert_eq!(report.strategy, PeelStrategy::DetectOnlyNativeOrVm);
}

#[test]
fn routing_themida_dotnet_detects_and_routes_to_detect_only_vm_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Themida");
    let report: PeelReport = peel_themida_dotnet(&img).expect("peel");
    assert_eq!(report.protector, Protector::ThemidaDotnet);
    assert_eq!(report.strategy, PeelStrategy::DetectOnlyNativeOrVm);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("Themida-.NET static envelope")),
        "peel report must document the static envelope and native-VM wall"
    );
}

#[test]
fn routing_ilprotector_detects_and_routes_to_detect_only_vm_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Protect32.dll");
    let report: PeelReport = peel_ilprotector(&img).expect("peel");
    assert_eq!(report.protector, Protector::Ilprotector);
    assert_eq!(report.strategy, PeelStrategy::DetectOnlyNativeOrVm);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("ILProtector static recovery")
                && n.contains("bodies_recovered=")),
        "peel report must surface measured ILProtector body-recovery counts"
    );
}

#[test]
fn routing_maxtocode_detects_and_routes_to_detect_only_vm_strategy() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"MaxtoCode");
    let report: PeelReport = peel_maxtocode(&img).expect("peel");
    assert_eq!(report.protector, Protector::MaxToCode);
    assert_eq!(report.strategy, PeelStrategy::DetectOnlyNativeOrVm);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("MaxToCode static recovery")
                && n.contains("bodies_recovered=")),
        "peel report must surface measured MaxToCode body-recovery counts"
    );
}

#[test]
fn routing_peel_by_enum_dispatches_all_paid_protectors() {
    let all: [Protector; 15] = [
        Protector::DotnetReactor,
        Protector::EazfuscatorNet,
        Protector::SmartAssembly,
        Protector::BabelDotnet,
        Protector::DeepSea,
        Protector::SpicesNet,
        Protector::Skater,
        Protector::Dotfuscator,
        Protector::DotfuscatorCe,
        Protector::Goliath,
        Protector::CryptoObfuscator,
        Protector::AgileNet,
        Protector::ArmDot,
        Protector::ThemidaDotnet,
        Protector::Ilprotector,
    ];
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    for p in all {
        let r: PeelReport = peel_by(p, &img)
            .unwrap_or_else(|| panic!("peel_by must dispatch protector {p:?}"))
            .unwrap_or_else(|e: disrobe_pass_dotnet::Error| panic!("peel_by({p:?}) failed: {e}"));
        assert_eq!(r.protector, p);
        assert!(r.bytes_in > 0);
        assert_eq!(r.bytes_in, r.bytes_out);
    }
}

#[test]
fn routing_peel_by_dispatches_confuser_family_to_resource_extractor() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"ConfuserEx2 v1.6.0");
    embed_signature(&mut img, b"ConfusedByAttribute");
    for p in [Protector::ConfuserEx, Protector::ConfuserEx2] {
        let report: PeelReport = peel_by(p, &img)
            .unwrap_or_else(|| panic!("peel_by must dispatch {p:?} to its resource extractor"))
            .unwrap_or_else(|e: disrobe_pass_dotnet::Error| panic!("peel_by({p:?}) failed: {e}"));
        assert_eq!(report.protector, p);
        assert_eq!(
            report.bytes_in, report.bytes_out,
            "ConfuserEx peel is report/extract-only: no in-place byte rewrite"
        );
        assert!(!report.notes.is_empty());
    }
}

#[test]
fn routing_peel_by_handles_obfuscar_with_dedicated_peeler() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let report: PeelReport = peel_by(Protector::Obfuscar, &img)
        .expect("Obfuscar has a dedicated FOSS peeler")
        .expect("peel synthetic managed PE");
    assert_eq!(report.protector, Protector::Obfuscar);
    assert_eq!(
        report.bytes_in, report.bytes_out,
        "rename-only: no byte rewrite"
    );
}

#[test]
fn corpus_edgecases_baseline_reports_no_paid_watermarks() {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let report: PeelReport = peel_dotnet_reactor(&bytes).expect("peel reactor on baseline");
    assert!(
        report.attributes_stripped.is_empty(),
        "unprotected baseline must not contain Reactor watermarks; got {:?}",
        report.attributes_stripped
    );
    assert!(report.strings_total > 0);
}

#[test]
fn corpus_static_decoder_recovery_runs_on_real_confuserex2_without_crashing() {
    for rel in [
        HELLOAPP_CONFUSED_REL,
        EDGECASES_CONFUSED_REL,
        EDGECASES_BASELINE_REL,
    ] {
        let bytes: Vec<u8> = load(rel);
        let report: StaticDecryptReport =
            recover_static_decoders(&bytes).expect("static decoder scan");
        for c in &report.constants_recovered {
            assert_ne!(
                c.method_token, 0,
                "recovered constant carries a method token"
            );
        }
    }
}

#[test]
fn corpus_static_decoder_recovery_surfaces_in_peel_report() {
    let bytes: Vec<u8> = load(EDGECASES_CONFUSED_REL);
    let report: PeelReport = peel_babel_net(&bytes).expect("peel");
    if report.recovered_decoders == 0 {
        assert!(report.recovered_constants.is_empty());
    } else {
        assert!(
            report
                .recovered_constants
                .iter()
                .all(|c| c.method_token != 0)
        );
    }
}

#[test]
fn corpus_edgecases_baseline_classifies_human_names() {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let report: PeelReport = peel_smartassembly(&bytes).expect("peel sa on baseline");
    assert!(
        report.unobfuscatable_identifiers > report.renamable_identifiers,
        "human-authored EdgeCases megafile should classify mostly as human; got renamable={} human={}",
        report.renamable_identifiers,
        report.unobfuscatable_identifiers
    );
}
