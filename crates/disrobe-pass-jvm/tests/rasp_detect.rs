#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_jvm::rasp::{RaspReport, RaspVendor, detect_in_dex};
use disrobe_pass_jvm::{DexFile, detect_rasp_in_apk, parse_dex};

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

#[test]
fn clean_edgecases_dex_has_no_rasp_false_positive() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let dex: DexFile = parse_dex(&dex_bytes).expect("parse");
    let report: RaspReport = detect_in_dex(&dex);
    assert!(
        !report.is_protected(),
        "clean (non-shielded) EdgeCases.dex must not trigger any RASP signal, got: {:?}",
        report.signals
    );
    assert!(!report.notes.is_empty(), "must record a detect-only note");
}

#[test]
fn clean_hello_dex_has_no_rasp_false_positive() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "Hello.dex"])).expect("dex");
    let dex: DexFile = parse_dex(&dex_bytes).expect("parse");
    let report: RaspReport = detect_in_dex(&dex);
    assert!(!report.is_protected(), "clean Hello.dex must not flag RASP");
}

#[test]
fn clean_signed_apk_has_no_rasp_false_positive() {
    let apk_bytes: Vec<u8> =
        std::fs::read(corpus(&["apk", "fixture-v2v3-signed.apk"])).expect("apk");
    let report: RaspReport = detect_rasp_in_apk(&apk_bytes).expect("detect");
    assert!(
        !report.is_protected(),
        "our own clean built apk must not flag any RASP vendor, got {:?}",
        report.signals
    );
}

#[test]
fn all_known_vendors_are_distinct() {
    let vendors: [RaspVendor; 8] = [
        RaspVendor::PromonShield,
        RaspVendor::GuardsquareDexGuard,
        RaspVendor::GuardsquareThreatCast,
        RaspVendor::AppdomeMobileShield,
        RaspVendor::OneSpan,
        RaspVendor::Arxan,
        RaspVendor::Zimperium,
        RaspVendor::BuildSecureDexProtector,
    ];
    let names: std::collections::BTreeSet<&str> =
        vendors.iter().map(|v: &RaspVendor| v.name()).collect();
    assert_eq!(names.len(), vendors.len(), "vendor names must be unique");
}
