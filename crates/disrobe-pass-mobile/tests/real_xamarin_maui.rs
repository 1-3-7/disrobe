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

use disrobe_pass_mobile::{
    AssemblyStoreHeader, XAMARIN_ASSEMBLY_STORE_V2_MAGIC, XamarinKind, XamarinReport,
    extract_xamarin_bundle, parse_assembly_store_header,
};

fn maybe_real_apk_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("apk")
        .join("inbox")
        .join("maui-test1.apk")
}

#[test]
fn xamarin_assembly_store_v2_magic_constant_is_xamu_le() {
    let bytes: [u8; 4] = XAMARIN_ASSEMBLY_STORE_V2_MAGIC.to_le_bytes();
    assert_eq!(&bytes, b"XAMU");
}

#[test]
fn xamarin_synth_store_blob_parses() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&XAMARIN_ASSEMBLY_STORE_V2_MAGIC.to_le_bytes());
    blob.extend_from_slice(&2u32.to_le_bytes());
    blob.extend_from_slice(&5u32.to_le_bytes());
    blob.extend_from_slice(&5u32.to_le_bytes());
    blob.extend_from_slice(&80u32.to_le_bytes());
    let header: AssemblyStoreHeader = parse_assembly_store_header(&blob).expect("parse header");
    assert_eq!(header.magic, XAMARIN_ASSEMBLY_STORE_V2_MAGIC);
    assert_eq!(header.version, 2);
    assert_eq!(header.entry_count, 5);
}

#[test]
#[ignore = "user-action-required: drop a real MAUI APK at corpus/mobile/apk/inbox/maui-test1.apk; auto-download attempts failed against F-Droid + Microsoft samples"]
fn maui_real_apk_extracts_assembly_store_when_present() {
    let path: PathBuf = maybe_real_apk_path();
    if !path.exists() {
        eprintln!(
            "skip: no real MAUI APK at {:?} — drop one in to enable this test",
            path
        );
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read maui apk");
    let report: XamarinReport = extract_xamarin_bundle(&bytes).expect("extract xamarin");
    assert!(
        matches!(
            report.kind,
            XamarinKind::AssemblyStoreV1
                | XamarinKind::AssemblyStoreV2
                | XamarinKind::MauiSingleFile
                | XamarinKind::LegacyDll
        ),
        "unexpected kind {:?}",
        report.kind
    );
    assert!(!report.assemblies.is_empty(), "expected assemblies");
}
