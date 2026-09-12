#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::{Detection, FreezerKind, PyfreezeOutput, detect_bytes, extract};

const BANDS: &[&str] = &[
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
];

fn corpus_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("freezers");
    p
}

fn fixture_path() -> PathBuf {
    corpus_root().join("zipapp").join("hello.pyz")
}

#[test]
fn zipapp_real_fixture_present() {
    let path: PathBuf = fixture_path();
    assert!(
        path.is_file(),
        "real zipapp fixture missing at {} - regenerate via DISROBE_ZIPAPP_REGEN per corpus/python/freezers/MANIFEST.toml",
        path.display()
    );
}

#[test]
fn zipapp_real_fixture_detects_as_zipapp() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_zipapp] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(det.kind, FreezerKind::Zipapp, "got: {det:?}");
}

#[test]
fn zipapp_real_fixture_contains_all_edge_case_bands() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_zipapp] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(std::io::Cursor::new(skip_shebang(&bytes))).expect("zip parse");
    let mut names: BTreeSet<String> = BTreeSet::new();
    for i in 0..archive.len() {
        let f: zip::read::ZipFile<'_> = archive.by_index(i).expect("zip entry");
        names.insert(f.name().to_owned());
    }
    for band in BANDS {
        let needle: String = format!("{band}.py");
        let pyc_needle: String = format!("{band}.pyc");
        let present: bool = names
            .iter()
            .any(|n: &String| n == &needle || n == &pyc_needle);
        assert!(
            present,
            "edge_cases band `{band}` missing from real zipapp fixture; names={names:?}"
        );
    }
    assert!(
        names
            .iter()
            .any(|n| n == "__main__.py" || n == "__main__.pyc"),
        "zipapp entry point __main__ missing"
    );
}

#[test]
fn zipapp_real_fixture_extracts_entries() {
    let path: PathBuf = fixture_path();
    if !path.is_file() {
        eprintln!("[real_zipapp] skipped: fixture missing");
        return;
    }
    let purpose: String = format!("disrobe-zipapp-real-{pid}", pid = std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let out_dir: PathBuf = scratch.path().to_path_buf();
    let out: PyfreezeOutput = extract(&path, &out_dir).expect("zipapp extract");
    assert_eq!(out.detection.kind, FreezerKind::Zipapp);
    assert!(
        out.manifest
            .entries
            .iter()
            .any(|entry| entry.name == "__main__.py" || entry.name == "__main__.pyc"),
        "zipapp extraction must surface the entry point; entries={:?}",
        out.manifest
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<&str>>()
    );
    assert!(
        out.extracted_count >= BANDS.len(),
        "zipapp extraction should surface the edge-case module set"
    );
}

fn skip_shebang(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(b"#!") {
        let nl: usize = bytes
            .iter()
            .position(|b: &u8| *b == b'\n')
            .map_or(0, |n: usize| n + 1);
        &bytes[nl..]
    } else {
        bytes
    }
}
