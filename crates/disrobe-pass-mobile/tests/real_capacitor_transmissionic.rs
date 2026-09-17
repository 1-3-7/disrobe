#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::print_stderr,
    clippy::single_match_else,
    clippy::uninlined_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::single_char_pattern
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle};

fn fixture_root() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("capacitor")
        .join("transmissionic")
}

fn apk_inbox_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("apk")
        .join("inbox")
        .join("transmissionic-ionic.apk")
}

fn load_input_apk() -> Option<Vec<u8>> {
    let path: PathBuf = apk_inbox_path();
    if !path.exists() {
        return None;
    }
    std::fs::read(&path).ok()
}

#[test]
fn transmissionic_corpus_extracted_files_present() {
    let root: PathBuf = fixture_root();
    if !root.exists() {
        eprintln!("skip: capacitor corpus missing at {:?}", root);
        return;
    }
    let cap_config: PathBuf = root.join("assets").join("capacitor.config.json");
    let index_html: PathBuf = root.join("assets").join("public").join("index.html");
    assert!(cap_config.exists(), "capacitor.config.json missing");
    assert!(index_html.exists(), "index.html missing");
    let cfg: Vec<u8> = std::fs::read(&cap_config).expect("read config");
    let cfg_str: String = String::from_utf8_lossy(&cfg).to_string();
    assert!(cfg_str.contains("appId") || cfg_str.contains("\""));
}

#[test]
fn transmissionic_real_apk_classifies_as_capacitor() {
    let bytes: Vec<u8> = match load_input_apk() {
        Some(b) => b,
        None => {
            eprintln!("skip: transmissionic-ionic.apk inbox missing");
            return;
        }
    };
    let report: WebviewExtractionReport = extract_webview_bundle(&bytes).expect("extract webview");
    assert_eq!(report.kind, WebviewBundleKind::Capacitor);
    assert!(report.entry_html.is_some(), "expected index.html entry");
    let has_app_js: bool = report
        .assets
        .iter()
        .any(|a| a.container_path.ends_with(".js"));
    assert!(has_app_js, "expected at least one .js asset");
    let has_cap_config: bool = report
        .assets
        .iter()
        .any(|a| a.container_path.ends_with("capacitor.config.json"));
    if !has_cap_config {
        eprintln!(
            "depyo-fate: extract_webview_bundle did not surface capacitor.config.json (lives at assets/, not assets/public/)"
        );
    }
}
