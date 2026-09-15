#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{
    BinaryFormat, NuitkaVariant, VariantClassification, classify_in_file, detect_in_bytes,
};

fn real_fixture(leaf: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("nuitka")
        .join("real")
        .join(leaf)
}

fn read_committed(leaf: &str) -> Vec<u8> {
    let path: PathBuf = real_fixture(leaf);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read committed fixture {}: {e}", path.display())
    })
}

#[test]
fn real_standalone_classifies_and_detects_nuitka_markers() {
    let path: PathBuf = real_fixture("sample_app-standalone.exe");
    let classification: VariantClassification =
        classify_in_file(&path).expect("classify standalone");
    assert_eq!(classification.binary_format, BinaryFormat::Pe);
    assert!(
        matches!(
            classification.variant,
            NuitkaVariant::Standalone | NuitkaVariant::Module | NuitkaVariant::SignedPe
        ),
        "expected standalone-family variant, got {:?}",
        classification.variant
    );

    let bytes: Vec<u8> = read_committed("sample_app-standalone.exe");
    let det = detect_in_bytes(&bytes).expect("detect standalone");
    assert!(
        det.hits
            .iter()
            .any(|h| h == "nuitka_module_loader" || h == "__compiled__"),
        "standalone must carry Nuitka loader markers; hits={:?}",
        det.hits
    );
}

#[test]
fn real_onefile_classifies_and_detects_nuitka_markers() {
    let path: PathBuf = real_fixture("sample_app-onefile.exe");
    let classification: VariantClassification = classify_in_file(&path).expect("classify onefile");
    assert_eq!(classification.binary_format, BinaryFormat::Pe);
    assert!(
        matches!(
            classification.variant,
            NuitkaVariant::OnefileKay
                | NuitkaVariant::OnefileKax
                | NuitkaVariant::Standalone
                | NuitkaVariant::SignedPe
        ),
        "expected onefile-family variant, got {:?}",
        classification.variant
    );

    let bytes: Vec<u8> = read_committed("sample_app-onefile.exe");
    let det = detect_in_bytes(&bytes).expect("detect onefile");
    assert!(
        det.hits.iter().any(|h| h.starts_with("NUITKA_ONEFILE_")),
        "onefile bootstrap must carry NUITKA_ONEFILE_* markers; hits={:?}",
        det.hits
    );
}
