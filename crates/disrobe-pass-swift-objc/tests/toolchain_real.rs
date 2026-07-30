#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::{CpuKind, ParsedSlice};
use disrobe_pass_swift_objc::toolchain::{self, SymbolState, ToolchainReport};

use macho_corpus::{
    EDGE_CASES_FAT, SWIFT_HELLO_ORIGINAL, first_slice, read_tracked, slice_preferring,
};

fn swift_hello_report() -> ToolchainReport {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let (_, parsed): (Vec<u8>, ParsedSlice) = first_slice(SWIFT_HELLO_ORIGINAL, &bytes);
    toolchain::report(&parsed)
}

#[test]
fn swift_hello_is_reported_as_a_pie_macos_executable() {
    let report: ToolchainReport = swift_hello_report();
    assert_eq!(report.file_type, "executable");
    assert_eq!(report.platform.as_deref(), Some("macos"));
    assert_eq!(report.min_os_version.as_deref(), Some("11.0.0"));
    assert_eq!(report.sdk_version.as_deref(), Some("26.5.0"));
    assert!(
        report.position_independent,
        "a modern macOS executable is position independent"
    );
    assert!(report.has_uuid);
}

#[test]
fn swift_and_objc_runtime_linkage_is_reported_separately() {
    let report: ToolchainReport = swift_hello_report();
    assert!(
        report.links_swift_runtime,
        "this image links libswiftCore, which is what makes Swift metadata worth reading"
    );
    assert!(
        report.links_objc_runtime,
        "it also links libobjc, so ObjC metadata is worth reading too"
    );
    assert_eq!(
        report.swift_runtime_dylibs.len(),
        8,
        "eight Swift runtime dylibs are linked: {:?}",
        report.swift_runtime_dylibs
    );
    assert!(
        report
            .swift_runtime_dylibs
            .contains(&"/usr/lib/swift/libswiftCore.dylib".to_owned()),
        "{:?}",
        report.swift_runtime_dylibs
    );
    assert_eq!(report.dylib_count, 11);
}

#[test]
fn the_swift_toolchain_version_is_read_out_of_the_rpaths() {
    let report: ToolchainReport = swift_hello_report();
    assert_eq!(
        report.swift_toolchain_rpath_hints,
        vec!["swift-5.5".to_owned(), "swift-6.2".to_owned()],
        "the toolchain rpaths name the Swift versions this image was built against"
    );
}

#[test]
fn an_unstripped_image_says_its_local_symbols_are_present() {
    let report: ToolchainReport = swift_hello_report();
    assert_eq!(report.symbol_state, SymbolState::LocalSymbolsPresent);
    assert_eq!(report.local_symbol_count, 186);
    assert_eq!(report.total_symbol_count, 227);
    assert!(
        report.symbol_state_note.contains("readable without"),
        "the report must say what the symbol state buys the analyst: {}",
        report.symbol_state_note
    );
}

#[test]
fn each_slice_of_a_fat_binary_reports_its_own_toolchain() {
    let bytes: Vec<u8> = read_tracked(EDGE_CASES_FAT);
    let (_, x86): (Vec<u8>, ParsedSlice) =
        slice_preferring(EDGE_CASES_FAT, &bytes, CpuKind::X86_64);
    let (_, arm): (Vec<u8>, ParsedSlice) = slice_preferring(EDGE_CASES_FAT, &bytes, CpuKind::Arm64);
    let x86_report: ToolchainReport = toolchain::report(&x86);
    let arm_report: ToolchainReport = toolchain::report(&arm);
    assert_eq!(x86_report.file_type, "executable");
    assert_eq!(arm_report.file_type, "executable");
    assert_eq!(
        x86_report.platform, arm_report.platform,
        "both slices target the same platform"
    );
    assert!(
        x86_report.total_symbol_count > 0 && arm_report.total_symbol_count > 0,
        "both slices carry symbols"
    );
}
