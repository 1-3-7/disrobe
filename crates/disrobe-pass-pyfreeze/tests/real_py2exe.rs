#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::py2exe::{Py2exeExtraction, detect_and_extract};
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
    p.push("py2exe");
    p
}

fn fixture_path() -> PathBuf {
    fixture_dir().join("hello.exe")
}

fn library_zip_path() -> PathBuf {
    fixture_dir().join("extracted").join("library.zip")
}

fn out_dir(tag: &str) -> PathBuf {
    let mut p: PathBuf = std::env::temp_dir();
    p.push(format!(
        "disrobe-real-py2exe-{tag}-{pid}-{nonce}",
        pid = std::process::id(),
        nonce = next_nonce()
    ));
    p
}

fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0x1234_5678);
    N.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn py2exe_real_fixture_detects_as_py2exe() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!(
            "[real_py2exe] skipped: fixture missing at {}",
            path.display()
        );
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(
        det.kind,
        FreezerKind::Py2exe,
        "real py2exe binary must be detected; got {det:?}"
    );
    assert!(
        det.confidence > 0.5,
        "py2exe detection confidence too low: {}",
        det.confidence
    );
}

#[test]
fn py2exe_real_fixture_extracts_pythonscript_resource() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_py2exe] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let out: PathBuf = out_dir("script");
    let extraction: Py2exeExtraction =
        detect_and_extract(&bytes, &path, &out).expect("py2exe extraction");
    assert!(
        !extraction.script_info.marshalled_code.is_empty(),
        "PYTHONSCRIPT marshalled code must not be empty"
    );
    assert!(
        extraction.embedded_pyc_path.is_file(),
        "embedded __pythonscript__.pyc must be written to disk"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn py2exe_sibling_library_zip_contains_all_edge_case_bands() {
    let path: PathBuf = library_zip_path();
    if !path.is_file() {
        eprintln!(
            "[real_py2exe] skipped: sibling library.zip missing at {}",
            path.display()
        );
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read library.zip");
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(std::io::Cursor::new(bytes.as_slice())).expect("zip parse");
    let mut names: BTreeSet<String> = BTreeSet::new();
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile<'_> = archive.by_index(i).expect("zip entry");
        names.insert(file.name().to_owned());
        let _ = file.read(&mut [0u8; 0]);
    }
    for band in BANDS {
        let pyc: String = format!("{band}.pyc");
        let py: String = format!("{band}.py");
        let present: bool = names.iter().any(|n: &String| n == &pyc || n == &py);
        assert!(
            present,
            "edge_cases band `{band}` missing from py2exe library.zip; sample={:?}",
            names.iter().take(10).collect::<Vec<&String>>()
        );
    }
}
