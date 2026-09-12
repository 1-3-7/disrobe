#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::pex::{PexExtraction, detect_and_extract};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, detect_bytes};

const BANDS: &[&str] = &[
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
];

fn fixture_path() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("freezers");
    p.push("pex");
    p.push("hello.pex");
    p
}

fn out_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!(
        "disrobe-real-pex-{tag}-{pid}-{nonce}",
        pid = std::process::id(),
        nonce = next_nonce()
    );
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xFEED_FACE);
    N.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn pex_real_fixture_detects_as_pex() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_pex] skipped: fixture missing at {}", path.display());
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(
        det.kind,
        FreezerKind::Pex,
        "real pex fixture must be detected; got {det:?}"
    );
    assert!(
        det.confidence > 0.5,
        "pex detection confidence too low: {}",
        det.confidence
    );
}

#[test]
fn pex_real_fixture_extracts_all_edge_case_bands_inside_deps_wheel() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_pex] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let scratch: disrobe_core::scratch::ScratchDir = out_dir("extract");
    let out: PathBuf = scratch.path().to_path_buf();
    let extraction: PexExtraction =
        detect_and_extract(&bytes, &path, &out).expect("pex extraction");
    let names: BTreeSet<String> = extraction
        .extracted
        .iter()
        .map(|e: &disrobe_pass_pyfreeze::pex::ExtractedEntry| e.name.clone())
        .collect();
    for band in BANDS {
        let suffix: String = format!("{band}.py");
        let present: bool = names.iter().any(|n: &String| n.ends_with(suffix.as_str()));
        assert!(
            present,
            "edge_cases band `{band}` missing from real pex extraction; names_sample={:?}",
            names.iter().take(20).collect::<Vec<&String>>()
        );
    }
    assert!(
        extraction
            .pex_info
            .entry_point
            .as_deref()
            .is_some_and(|ep: &str| ep.starts_with("hello")),
        "PEX-INFO entry_point must reference hello; got {:?}",
        extraction.pex_info.entry_point
    );
}
