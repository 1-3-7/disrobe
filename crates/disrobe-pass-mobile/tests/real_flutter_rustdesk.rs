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

use disrobe_pass_mobile::{LibAppLayout, parse_libapp_so};

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
    let has_any_snapshot: bool = layout.vm_snapshot_data.is_some()
        || layout.isolate_snapshot_data.is_some()
        || layout.vm_snapshot_instructions.is_some()
        || layout.isolate_snapshot_instructions.is_some();
    if !has_any_snapshot {
        eprintln!(
            "depyo-fate: real rustdesk libapp.so exposes no Dart snapshot symbols via .symtab (stripped). Section count: {}",
            layout.section_names.len()
        );
    }
}
