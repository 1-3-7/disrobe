#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::shiv::{ShivExtraction, detect_and_extract};
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
    p.push("shiv");
    p.push("hello.pyz");
    p
}

fn out_dir(tag: &str) -> PathBuf {
    let mut p: PathBuf = std::env::temp_dir();
    p.push(format!(
        "disrobe-real-shiv-{tag}-{pid}-{nonce}",
        pid = std::process::id(),
        nonce = next_nonce()
    ));
    p
}

fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xDEAD_BEEF);
    N.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn shiv_real_fixture_detects_as_shiv() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_shiv] skipped: fixture missing at {}", path.display());
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(
        det.kind,
        FreezerKind::Shiv,
        "real shiv fixture must be detected; got {det:?}"
    );
    assert!(
        det.confidence > 0.5,
        "shiv detection confidence too low: {}",
        det.confidence
    );
}

#[test]
fn shiv_real_fixture_extracts_all_edge_case_bands_as_source() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_shiv] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let out: PathBuf = out_dir("extract");
    let extraction: ShivExtraction =
        detect_and_extract(&bytes, &path, &out).expect("shiv extraction");
    let names: BTreeSet<String> = extraction
        .extracted
        .iter()
        .map(|e: &disrobe_pass_pyfreeze::shiv::ExtractedEntry| e.name.clone())
        .collect();
    for band in BANDS {
        let needle_py: String = format!("site-packages/{band}.py");
        let needle_pyc: String = format!("site-packages/{band}.pyc");
        let present: bool = names
            .iter()
            .any(|n: &String| n == &needle_py || n == &needle_pyc);
        assert!(
            present,
            "edge_cases band `{band}` missing from real shiv extraction; names={names:?}"
        );
    }
    assert!(
        extraction.manifest.entry_count >= BANDS.len(),
        "manifest must have at least {} entries, got {}",
        BANDS.len(),
        extraction.manifest.entry_count
    );
    assert!(
        extraction
            .environment
            .entry_point
            .as_deref()
            .is_some_and(|ep: &str| ep.starts_with("hello")),
        "shiv environment.json entry_point must reference `hello`, got {:?}",
        extraction.environment.entry_point
    );
    let _ = std::fs::remove_dir_all(&out);
}
