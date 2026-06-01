#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::briefcase::{BriefcaseExtraction, detect_and_extract};
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
    p.push("briefcase");
    p
}

fn binary_path() -> PathBuf {
    fixture_dir().join("extracted").join("hello.exe")
}

#[test]
fn briefcase_real_fixture_detects_via_sibling_layout() {
    let path: PathBuf = binary_path();
    if !path.is_file() {
        eprintln!(
            "[real_briefcase] skipped: fixture missing at {}",
            path.display()
        );
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(
        det.kind,
        FreezerKind::Briefcase,
        "real briefcase binary must be detected via sibling app_packages/ layout; got {det:?}"
    );
    assert!(
        det.confidence > 0.5,
        "briefcase detection confidence too low: {}",
        det.confidence
    );
}

#[test]
fn briefcase_real_fixture_indexes_all_edge_case_bands() {
    let path: PathBuf = binary_path();
    if !path.is_file() {
        eprintln!("[real_briefcase] skipped: fixture missing");
        return;
    }
    let extraction: BriefcaseExtraction = detect_and_extract(&path).expect("briefcase extraction");
    let names: BTreeSet<String> = extraction
        .indexed_modules
        .iter()
        .map(|e: &disrobe_pass_pyfreeze::common::manifest::EntryRecord| e.name.clone())
        .collect();
    for band in BANDS {
        let suffix: String = format!("{band}.py");
        let present: bool = names.iter().any(|n: &String| n.ends_with(suffix.as_str()));
        assert!(
            present,
            "edge_cases band `{band}` missing from briefcase app/ tree; sample={:?}",
            names.iter().take(10).collect::<Vec<&String>>()
        );
    }
    assert!(
        extraction.layout.app_packages_dir.is_some()
            || extraction.layout.python_stdlib_dir.is_some(),
        "briefcase layout must surface either app_packages/ or python-stdlib/"
    );
}
