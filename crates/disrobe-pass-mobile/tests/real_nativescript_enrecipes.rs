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

use disrobe_pass_mobile::{NativeScriptBundle, NativeScriptReport, extract_nativescript_bundle};

fn corpus_root() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("nativescript")
        .join("enrecipes")
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
        .join("enrecipes-nativescript.apk")
}

fn load_input_apk() -> Option<Vec<u8>> {
    let path: PathBuf = apk_inbox_path();
    if !path.exists() {
        return None;
    }
    std::fs::read(&path).ok()
}

#[test]
fn enrecipes_corpus_assets_present() {
    let root: PathBuf = corpus_root();
    if !root.exists() {
        eprintln!("skip: nativescript corpus missing");
        return;
    }
    for name in [
        "bundle.js",
        "vendor.js",
        "runtime.js",
        "package.json",
        "libNativeScript.so",
    ] {
        let p: PathBuf = root.join(name);
        assert!(p.exists(), "missing {name}");
    }
}

#[test]
fn enrecipes_libnativescript_is_elf() {
    let p: PathBuf = corpus_root().join("libNativeScript.so");
    if !p.exists() {
        eprintln!("skip: libNativeScript.so missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&p).expect("read");
    assert!(bytes.len() > 1024);
    assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F']);
}

#[test]
fn enrecipes_real_apk_extracts_nativescript_bundle() {
    let bytes: Vec<u8> = match load_input_apk() {
        Some(b) => b,
        None => {
            eprintln!("skip: enrecipes-nativescript.apk missing");
            return;
        }
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
    if !pkg_present {
        eprintln!(
            "depyo-fate: package.json not surfaced by extract_nativescript_bundle for enrecipes APK"
        );
    }
}
