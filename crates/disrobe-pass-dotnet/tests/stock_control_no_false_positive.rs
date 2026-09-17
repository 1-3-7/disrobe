#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::peel::obfuscar::detect_obfuscar;
use disrobe_pass_dotnet::protectors::{DetectionReport, Protector, detect_all};

const STOCK_CONTROLS: [&str; 4] = [
    "../../corpus/dotnet/stock_control/ReflectionControl.dll",
    "../../corpus/dotnet/stock_control/RecordControl.dll",
    "../../corpus/dotnet/stock_control/LinqControl.dll",
    "../../corpus/dotnet/stock_control/ThreadingControl.dll",
];

const REAL_OBFUSCAR: [&str; 2] = [
    "../../corpus/dotnet/HelloAppLegacy.obfuscar.dll",
    "../../corpus/dotnet/megafile/EdgeCases.obfuscar.dll",
];

const REAL_CONFUSEREX2: [&str; 2] = [
    "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll",
    "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll",
];

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn stock_controls_analyze_clean_no_protector() {
    for rel in STOCK_CONTROLS {
        let bytes: Vec<u8> = load(rel);
        let summary: PassSummary = analyze(&bytes).expect("analyze stock control");
        assert_eq!(
            summary.primary_protector, None,
            "stock unobfuscated control {rel} must flag no primary protector; got {:?}",
            summary.primary_protector
        );
        assert!(
            summary.protectors_detected.is_empty(),
            "stock unobfuscated control {rel} must list zero protectors; got {:?}",
            summary.protectors_detected
        );
    }
}

#[test]
fn stock_controls_detect_all_finds_nothing() {
    for rel in STOCK_CONTROLS {
        let bytes: Vec<u8> = load(rel);
        let report: DetectionReport = detect_all(&bytes);
        assert_eq!(
            report.primary, None,
            "detect_all must not name a protector on stock control {rel}; got {:?}",
            report.primary
        );
        assert!(
            report.matches.is_empty(),
            "detect_all must yield no matches on stock control {rel}; got {:?}",
            report.matches.keys().collect::<Vec<&Protector>>()
        );
    }
}

#[test]
fn stock_controls_not_flagged_as_obfuscar() {
    for rel in STOCK_CONTROLS {
        let bytes: Vec<u8> = load(rel);
        assert!(
            !detect_obfuscar(&bytes),
            "Obfuscar odometer heuristic false-positived on stock control {rel}"
        );
    }
}

#[test]
fn real_obfuscar_fixtures_still_detect() {
    for rel in REAL_OBFUSCAR {
        let bytes: Vec<u8> = load(rel);
        let summary: PassSummary = analyze(&bytes).expect("analyze obfuscar fixture");
        assert_eq!(
            summary.primary_protector,
            Some(Protector::Obfuscar),
            "real Obfuscar fixture {rel} must still detect (no false-negative); got {:?}",
            summary.primary_protector
        );
        assert!(
            detect_obfuscar(&bytes),
            "Obfuscar heuristic must still fire on real fixture {rel}"
        );
    }
}

#[test]
fn real_confuserex2_fixtures_still_detect() {
    for rel in REAL_CONFUSEREX2 {
        let bytes: Vec<u8> = load(rel);
        let summary: PassSummary = analyze(&bytes).expect("analyze confuserex2 fixture");
        assert!(
            summary
                .protectors_detected
                .iter()
                .any(|p: &Protector| matches!(p, Protector::ConfuserEx | Protector::ConfuserEx2)),
            "real ConfuserEx2 fixture {rel} must still detect (no false-negative); got {:?}",
            summary.protectors_detected
        );
    }
}
