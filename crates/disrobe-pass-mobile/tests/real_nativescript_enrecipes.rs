#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::single_match_else,
    clippy::uninlined_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::single_char_pattern
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{NativeScriptBundle, NativeScriptReport, extract_nativescript_bundle};

fn apk_inbox_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("apk")
        .join("inbox")
        .join("enrecipes-nativescript.apk")
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
fn enrecipes_real_apk_extracts_nativescript_bundle() {
    let Some(bytes): Option<Vec<u8>> = local_apk() else {
        return;
    };
    let report: NativeScriptReport = extract_nativescript_bundle(&bytes).expect("extract");
    assert!(
        report.has_runtime_marker,
        "expected ts_helpers.js or package.json"
    );
    let names: Vec<&str> = report
        .bundles
        .iter()
        .map(|b: &NativeScriptBundle| b.container_path.as_str())
        .collect();
    assert!(
        names.contains(&"assets/app/bundle.js"),
        "missing bundle.js, got: {:?}",
        names
    );
    let pkg_present: bool = names.iter().any(|n: &&str| n.ends_with("package.json"));
    assert!(
        pkg_present,
        "package.json must be extracted with the bundles"
    );
    let mut sorted: Vec<&str> = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        [
            "assets/app/bundle.js",
            "assets/app/package.json",
            "assets/app/runtime.js",
            "assets/app/vendor.js"
        ]
    );
}
