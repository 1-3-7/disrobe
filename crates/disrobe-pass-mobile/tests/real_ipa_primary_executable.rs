#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{IpaExtractionReport, extract_ipa};

fn ipa_path(stem: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("ipa")
        .join(format!("{stem}.ipa"))
}

fn load(stem: &str) -> Option<Vec<u8>> {
    let path: PathBuf = ipa_path(stem);
    if !path.exists() {
        eprintln!("skip: ipa fixture missing at {}", path.display());
        return None;
    }
    std::fs::read(&path).ok()
}

fn assert_primary(stem: &str, expected_basename: &str) {
    let Some(bytes): Option<Vec<u8>> = load(stem) else {
        return;
    };
    let report: IpaExtractionReport = extract_ipa(&bytes).expect("extract ipa");
    let primary: &str = report
        .primary_executable
        .as_deref()
        .unwrap_or_else(|| panic!("{stem}: no primary executable selected"));
    let basename: &str = primary.rsplit('/').next().unwrap_or(primary);
    assert_eq!(
        basename, expected_basename,
        "{stem}: primary executable must be the .app bundle binary, got {primary:?}",
    );
    assert!(
        !primary.contains("_CodeSignature"),
        "{stem}: _CodeSignature/CodeResources must never be selected as the executable ({primary:?})",
    );
    assert!(
        report
            .entries
            .iter()
            .all(|e| !(e.is_executable && e.container_path.contains("/_CodeSignature/"))),
        "{stem}: no _CodeSignature entry may be flagged is_executable",
    );
}

#[test]
fn feather_primary_executable_is_app_binary_not_codesignature() {
    assert_primary("Feather-2.8.2", "Feather");
}

#[test]
fn onion_browser_primary_executable_is_app_binary() {
    assert_primary("OnionBrowser-3.3.8", "OnionBrowser");
}

#[test]
fn ppsspp_primary_executable_is_app_binary() {
    assert_primary("PPSSPP-v1.20.4", "PPSSPP");
}
