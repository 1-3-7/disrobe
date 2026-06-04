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
    DART_ISOLATE_DATA_SYMBOL, DART_ISOLATE_INSTR_SYMBOL, DART_SNAPSHOT_MAGIC, DART_VM_DATA_SYMBOL,
    DART_VM_INSTR_SYMBOL, DartSnapshotHeader, DartSnapshotKind, DartStaticRecovery, LibAppLayout,
    SnapshotSection, decompile_libapp_so, parse_dart_snapshot, parse_libapp_so,
};

fn fixture_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("rustdesk")
        .join("libapp.so")
}

fn libflutter_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("rustdesk")
        .join("libflutter.so")
}

fn load_fixture(path: &Path) -> Option<Vec<u8>> {
    if !path.exists() {
        return None;
    }
    std::fs::read(path).ok()
}

#[test]
fn rustdesk_libapp_so_is_elf() {
    let bytes: Vec<u8> = match load_fixture(&fixture_path()) {
        Some(b) => b,
        None => {
            eprintln!("skip: libapp.so fixture missing");
            return;
        }
    };
    assert!(bytes.len() > 1024);
    assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F']);
    assert_eq!(bytes[4], 2, "expected ELF64");
}

#[test]
fn rustdesk_libflutter_so_is_elf() {
    let bytes: Vec<u8> = match load_fixture(&libflutter_path()) {
        Some(b) => b,
        None => {
            eprintln!("skip: libflutter.so fixture missing");
            return;
        }
    };
    assert!(bytes.len() > 1024);
    assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F']);
}

fn assert_recovered(section: Option<&SnapshotSection>, expected_symbol: &str) -> SnapshotSection {
    let s: &SnapshotSection = section.unwrap_or_else(|| {
        panic!("Dart snapshot symbol {expected_symbol} not recovered (was MISSING regression)")
    });
    assert_eq!(s.symbol, expected_symbol, "symbol name mismatch");
    assert!(
        s.address > 0,
        "{expected_symbol} must have a nonzero virtual address, got {:#x}",
        s.address
    );
    assert!(
        s.size > 0,
        "{expected_symbol} must have a nonzero size, got {}",
        s.size
    );
    s.clone()
}

#[test]
fn rustdesk_libapp_parse_finds_dart_snapshot_symbols() {
    let bytes: Vec<u8> = match load_fixture(&fixture_path()) {
        Some(b) => b,
        None => {
            eprintln!("skip: libapp.so fixture missing");
            return;
        }
    };
    let layout: LibAppLayout = parse_libapp_so(&bytes).expect("parse libapp.so");
    assert!(
        !layout.section_names.is_empty(),
        "expected ELF sections enumerated"
    );
    assert!(
        layout.section_names.iter().any(|n: &String| n == ".dynsym"),
        "expected .dynsym present in real stripped libapp.so"
    );

    let vm_data: SnapshotSection =
        assert_recovered(layout.vm_snapshot_data.as_ref(), DART_VM_DATA_SYMBOL);
    let vm_instr: SnapshotSection = assert_recovered(
        layout.vm_snapshot_instructions.as_ref(),
        DART_VM_INSTR_SYMBOL,
    );
    let iso_data: SnapshotSection = assert_recovered(
        layout.isolate_snapshot_data.as_ref(),
        DART_ISOLATE_DATA_SYMBOL,
    );
    let iso_instr: SnapshotSection = assert_recovered(
        layout.isolate_snapshot_instructions.as_ref(),
        DART_ISOLATE_INSTR_SYMBOL,
    );

    assert!(
        iso_data.size > 4_000_000,
        "rustdesk isolate snapshot data is ~4.4MB, got {}",
        iso_data.size
    );
    assert!(
        iso_instr.size > 7_000_000,
        "rustdesk isolate instructions are ~7.5MB, got {}",
        iso_instr.size
    );

    for sec in [&vm_data, &iso_data] {
        let magic: u32 = u32::from_le_bytes([
            sec.bytes_preview[0],
            sec.bytes_preview[1],
            sec.bytes_preview[2],
            sec.bytes_preview[3],
        ]);
        assert_eq!(
            magic, DART_SNAPSHOT_MAGIC,
            "{} payload must begin with the Dart snapshot magic",
            sec.symbol
        );
    }

    let header: DartSnapshotHeader =
        parse_dart_snapshot(&vm_data.bytes_preview).expect("parse VM snapshot header");
    assert_eq!(header.magic, DART_SNAPSHOT_MAGIC);
    assert_eq!(header.kind, DartSnapshotKind::FullAot);
    assert_eq!(header.version_hash.len(), 32);
    assert!(
        header
            .version_hash
            .bytes()
            .all(|b: u8| b.is_ascii_hexdigit()),
        "version hash must be ascii-hex, got {}",
        header.version_hash
    );

    eprintln!(
        "recovered 4/4 Dart symbols: vm_data@{:#x}({}) vm_instr@{:#x}({}) iso_data@{:#x}({}) iso_instr@{:#x}({}); snapshot kind={:?} version={}",
        vm_data.address,
        vm_data.size,
        vm_instr.address,
        vm_instr.size,
        iso_data.address,
        iso_data.size,
        iso_instr.address,
        iso_instr.size,
        header.kind,
        header.version_hash
    );
}

#[test]
fn rustdesk_static_recovery_reports_raw_counts() {
    let bytes: Vec<u8> = match load_fixture(&fixture_path()) {
        Some(b) => b,
        None => {
            eprintln!(
                "skip: libapp.so fixture missing — no synthetic substitute; flutter aot recovery is only reported against the real binary's own snapshot string table"
            );
            return;
        }
    };
    let recovery: DartStaticRecovery =
        decompile_libapp_so(&bytes).expect("decompile real libapp.so");
    eprintln!(
        "rustdesk flutter aot RAW recovery (measured against the binary's own isolate snapshot): function_boundaries={} classes={} methods={} library_uris={} bodies_recovered=0 (arm64 register-erasure wall)",
        recovery.function_boundary_count,
        recovery.class_names.len(),
        recovery.method_names.len(),
        recovery.library_uris.len()
    );
    assert!(
        recovery.function_boundary_count > 0,
        "real instructions image must yield at least one ARM64 frame prologue"
    );
    assert!(
        recovery.class_names.len() + recovery.method_names.len() > 0,
        "real isolate data snapshot must yield at least one Dart identifier"
    );
}
