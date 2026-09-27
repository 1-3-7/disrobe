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

const REQUIRE_CORPUS_VAR: &str = "DISROBE_REQUIRE_MOBILE_CORPUS";

fn local_apk() -> Option<Vec<u8>> {
    if let Some(bytes) = load_input_apk() {
        return Some(bytes);
    }
    assert!(
        std::env::var_os(REQUIRE_CORPUS_VAR).is_none(),
        "{REQUIRE_CORPUS_VAR} is set, so the local-only APK under corpus/mobile/apk/inbox must exist"
    );
    eprintln!(
        "UNGRADED: the local-only APK under corpus/mobile/apk/inbox is absent; set {REQUIRE_CORPUS_VAR}=1 to fail instead"
    );
    None
}

#[test]
fn transmissionic_real_apk_classifies_as_capacitor() {
    let Some(bytes): Option<Vec<u8>> = local_apk() else {
        return;
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
    assert!(
        has_cap_config,
        "capacitor.config.json sits under assets/, beside the web root, and must be extracted"
    );
    assert_eq!(
        report.entry_html.as_deref(),
        Some("assets/public/index.html")
    );
}
