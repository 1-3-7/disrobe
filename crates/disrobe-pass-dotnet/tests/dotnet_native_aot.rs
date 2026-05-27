#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

use disrobe_pass_dotnet::aot::{AotReport, AotRuntime, detect};

#[test]
fn synthetic_aot_image_detected() {
    let mut img: Vec<u8> = vec![0u8; 2048];
    img[100..109].copy_from_slice(b"NativeAOT");
    img[200..210].copy_from_slice(b"RhpNewFast");
    img[400..406].copy_from_slice(b"net8.0");
    let report: AotReport = detect(&img);
    assert!(report.is_native_aot);
    assert_eq!(report.runtime_label, AotRuntime::Net8);
    assert!(report.recovered_symbols.contains_key("aot_marker"));
    assert!(report.recovered_symbols.contains_key("rhp_alloc"));
}

#[test]
#[ignore = "FIXTURE PENDING: real Native-AOT (.NET 8/9/10) binary from `dotnet publish -p:PublishAot=true`"]
fn real_native_aot_symbol_recovery() {
    panic!("FIXTURE PENDING");
}
