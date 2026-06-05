#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, peel_obfuscar};
use disrobe_pass_dotnet::protectors::{
    ExecuteOptions, ExecutionOutcome, GreyZone, Handling, Protector, plan_execution,
};

const HELLOAPP_OBFUSCAR_REL: &str = "../../corpus/dotnet/HelloAppLegacy.obfuscar.dll";
const EDGECASES_OBFUSCAR_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.obfuscar.dll";
const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const EDGECASES_CONFUSEREX2_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll";
const HELLOAPP_CONFUSEREX2_REL: &str = "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn obfuscar_helloapp_parses_as_managed_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_OBFUSCAR_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header survives renaming");
    let _root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata root");
}

#[test]
fn obfuscar_megafile_parses_as_managed_pe() {
    let bytes: Vec<u8> = load(EDGECASES_OBFUSCAR_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata root");
    assert!(!root.streams.is_empty());
}

#[test]
fn obfuscar_is_green_zone_native_strip() {
    assert_eq!(Protector::Obfuscar.grey_zone(), GreyZone::Green);
    let plan: ExecutionOutcome = plan_execution(Protector::Obfuscar, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}

#[test]
fn obfuscar_helloapp_detected_as_obfuscar() {
    let bytes: Vec<u8> = load(HELLOAPP_OBFUSCAR_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    assert_eq!(
        summary.primary_protector,
        Some(Protector::Obfuscar),
        "real Obfuscar fixture must detect as Obfuscar; got {:?}",
        summary.primary_protector
    );
    assert!(summary.protectors_detected.contains(&Protector::Obfuscar));
}

#[test]
fn obfuscar_megafile_detected_as_obfuscar() {
    let bytes: Vec<u8> = load(EDGECASES_OBFUSCAR_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    assert_eq!(
        summary.primary_protector,
        Some(Protector::Obfuscar),
        "real Obfuscar megafile must detect as Obfuscar; got {:?}",
        summary.primary_protector
    );
    assert!(summary.protectors_detected.contains(&Protector::Obfuscar));
}

#[test]
fn clean_baseline_not_flagged_as_obfuscar() {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    assert_eq!(
        summary.primary_protector, None,
        "clean baseline must flag no protector; got {:?}",
        summary.primary_protector
    );
}

#[test]
fn real_confuserex2_not_misclassified_as_obfuscar() {
    for rel in [EDGECASES_CONFUSEREX2_REL, HELLOAPP_CONFUSEREX2_REL] {
        let bytes: Vec<u8> = load(rel);
        let summary: PassSummary = analyze(&bytes).expect("analyze");
        assert_ne!(
            summary.primary_protector,
            Some(Protector::Obfuscar),
            "ConfuserEx2 fixture {rel} must not be misread as Obfuscar"
        );
        assert!(
            !summary.protectors_detected.contains(&Protector::Obfuscar),
            "ConfuserEx2 fixture {rel} must not list Obfuscar"
        );
    }
}

#[test]
fn obfuscar_peel_reports_renamed_slots_without_fabricating_names() {
    let bytes: Vec<u8> = load(HELLOAPP_OBFUSCAR_REL);
    let report: PeelReport = peel_obfuscar(&bytes).expect("peel");
    assert_eq!(report.protector, Protector::Obfuscar);
    assert_eq!(report.strategy, PeelStrategy::AttributeStripAndReport);
    assert!(
        report.bytes_out == report.bytes_in,
        "no byte rewrite claimed"
    );
    assert!(report.renamable_identifiers > 0, "renamed slots reported");
}

#[test]
fn obfuscar_megafile_bytes_differ_from_baseline() {
    let baseline: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let obfuscated: Vec<u8> = load(EDGECASES_OBFUSCAR_REL);
    assert_ne!(baseline, obfuscated, "renamed PE must differ from baseline");
}
