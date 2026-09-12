#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::cxfreeze::{CxFreezeExtraction, detect_and_extract};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, detect_bytes};

const BANDS: &[&str] = &[
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
];

fn fixture_dir() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("freezers");
    p.push("cxfreeze");
    p
}

fn binary_path() -> PathBuf {
    fixture_dir().join("extracted").join("hello.exe")
}

fn out_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!(
        "disrobe-real-cxfreeze-{tag}-{pid}-{nonce}",
        pid = std::process::id(),
        nonce = next_nonce()
    );
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xABCD_1234);
    N.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn cxfreeze_real_fixture_detects_as_cxfreeze() {
    let path: PathBuf = binary_path();
    if !path.is_file() {
        eprintln!(
            "[real_cxfreeze] skipped: fixture missing at {}",
            path.display()
        );
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(
        det.kind,
        FreezerKind::CxFreeze,
        "real cx_Freeze binary must be detected via sibling layout; got {det:?}"
    );
    assert!(
        det.confidence > 0.5,
        "cx_Freeze detection confidence too low: {}",
        det.confidence
    );
}

#[test]
fn cxfreeze_real_fixture_extracts_all_edge_case_bands_from_library_zip() {
    let path: PathBuf = binary_path();
    if !path.is_file() {
        eprintln!("[real_cxfreeze] skipped: fixture missing");
        return;
    }
    let scratch: disrobe_core::scratch::ScratchDir = out_dir("extract");
    let out: PathBuf = scratch.path().to_path_buf();
    let extraction: CxFreezeExtraction =
        detect_and_extract(&path, &out).expect("cxfreeze extraction");
    let names: BTreeSet<String> = extraction
        .extracted
        .iter()
        .map(|e: &disrobe_pass_pyfreeze::cxfreeze::library_zip::ExtractedEntry| e.name.clone())
        .collect();
    for band in BANDS {
        let pyc: String = format!("{band}.pyc");
        let present: bool = names.iter().any(|n: &String| n == &pyc);
        assert!(
            present,
            "edge_cases band `{band}` missing from cx_Freeze library.zip; sample={:?}",
            names.iter().take(10).collect::<Vec<&String>>()
        );
    }
    assert!(
        extraction.library_zip_path.is_some(),
        "cx_Freeze layout must locate library.zip"
    );
    assert!(
        extraction.manifest.entry_count >= BANDS.len(),
        "manifest must enumerate at least {} entries, got {}",
        BANDS.len(),
        extraction.manifest.entry_count
    );
}
