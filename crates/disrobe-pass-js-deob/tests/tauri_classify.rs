#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::tauri::{NativeBinaryKind, TauriBinaryClass, classify_tauri_binary};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PE_MZ: [u8; 2] = [b'M', b'Z'];
const MACHO_LE_64: u32 = 0xFEED_FACF;

#[test]
fn tauri_elf_with_wry_marker_classifies_as_tauri() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&ELF_MAGIC);
    bytes.extend(std::iter::repeat_n(0u8, 128));
    bytes.extend_from_slice(b"wry::application");
    let class: TauriBinaryClass = classify_tauri_binary(&bytes);
    assert_eq!(class.kind, NativeBinaryKind::Elf);
    assert!(class.is_tauri());
    assert!(class.has_wry_marker);
}

#[test]
fn tauri_pe_with_webview2_and_builder_markers() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&PE_MZ);
    bytes.extend(std::iter::repeat_n(0u8, 128));
    bytes.extend_from_slice(b"WebView2");
    bytes.extend(std::iter::repeat_n(0u8, 32));
    bytes.extend_from_slice(b"tauri::Builder");
    let class: TauriBinaryClass = classify_tauri_binary(&bytes);
    assert_eq!(class.kind, NativeBinaryKind::Pe);
    assert!(class.has_webview2_marker);
    assert!(class.has_tauri_builder_marker);
    assert!(class.is_tauri());
}

#[test]
fn tauri_macho_classification_with_marker() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&MACHO_LE_64.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0u8, 128));
    bytes.extend_from_slice(b"tauri::Builder");
    let class: TauriBinaryClass = classify_tauri_binary(&bytes);
    assert_eq!(class.kind, NativeBinaryKind::MachO);
    assert!(class.is_tauri());
}

#[test]
fn non_tauri_binary_correctly_negative() {
    let bytes: Vec<u8> = vec![0u8; 1024];
    let class: TauriBinaryClass = classify_tauri_binary(&bytes);
    assert!(!class.is_tauri());
    assert_eq!(class.kind, NativeBinaryKind::Unknown);
}

#[test]
#[ignore = "BLOCKER: real Tauri RCDATA / Mach-O __DATA / ELF .rodata payload carving needs a packaged Tauri app fixture (license-clean Tauri sample app build required) — defer to fixture sprint"]
fn tauri_real_app_payload_carve() {
    panic!("ignored: real Tauri fixture pending");
}
