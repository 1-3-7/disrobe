#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_binfmt::{
    ContainerKind, ExtractedEntry, ExtractionResult, detect_and_extract_with_hint, detect_container,
};

const OUTER_FV: &[u8] = include_bytes!("fixtures/uefi_fv/outer.fv");
const HELLO_A_EFI: &[u8] = include_bytes!("fixtures/uefi_fv/hello_a.efi");
const HELLO_B_EFI: &[u8] = include_bytes!("fixtures/uefi_fv/hello_b.efi");
const BROTLI_GUIDED_FV: &[u8] = include_bytes!("fixtures/uefi_fv/edk2_brotli_guided.fv");
const TIANO_GUIDED_FV: &[u8] = include_bytes!("fixtures/uefi_fv/edk2_tiano_guided.fv");

#[test]
fn auto_detect_classifies_a_real_edk2_built_firmware_volume_as_uefi_fv() {
    let kind: ContainerKind = detect_container(OUTER_FV).expect("detected");
    assert_eq!(kind, ContainerKind::UefiFv);
}

#[test]
fn top_level_detect_and_extract_recovers_the_driver_pe_without_calling_uefi_fv_directly() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-uefi-fv-dispatch")
            .expect("create scratch directory");
    let out_dir: std::path::PathBuf = scratch.path().join("out");

    let result: ExtractionResult =
        detect_and_extract_with_hint(OUTER_FV, None, &out_dir).expect("detect and extract");
    assert_eq!(result.kind, ContainerKind::UefiFv);

    let hello_a: &ExtractedEntry = result
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| e.name == "HelloA")
        .expect("HelloA entry written by the top-level dispatcher");
    let disk_path: &std::path::PathBuf = hello_a
        .disk_path
        .as_ref()
        .expect("HelloA was written to disk");
    let on_disk: Vec<u8> = std::fs::read(disk_path).expect("read HelloA");
    assert_eq!(on_disk.as_slice(), HELLO_A_EFI);

    let hello_b: &ExtractedEntry = result
        .entries
        .iter()
        .find(|entry: &&ExtractedEntry| entry.name == "HelloB")
        .expect("HelloB entry written by the top-level dispatcher");
    let hello_b_path: &std::path::PathBuf = hello_b
        .disk_path
        .as_ref()
        .expect("HelloB was written to disk");
    assert_eq!(
        std::fs::read(hello_b_path).expect("read HelloB"),
        HELLO_B_EFI
    );

    let summary_path: std::path::PathBuf = out_dir.join(".disrobe-uefi-fv.json");
    assert!(summary_path.exists());
}

#[test]
fn current_edk2_brotli_guided_firmware_recovers_its_only_driver_byte_for_byte() {
    assert!(
        !BROTLI_GUIDED_FV
            .windows(HELLO_A_EFI.len())
            .any(|window: &[u8]| window == HELLO_A_EFI),
        "the firmware fixture must not contain an uncompressed copy of the reference image"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-uefi-fv-brotli-dispatch")
            .expect("create scratch directory");
    let out_dir: std::path::PathBuf = scratch.path().join("out");
    let result: ExtractionResult = detect_and_extract_with_hint(BROTLI_GUIDED_FV, None, &out_dir)
        .expect("decode Brotli-guided firmware");
    assert_eq!(result.kind, ContainerKind::UefiFv);

    let driver: &ExtractedEntry = result
        .entries
        .iter()
        .find(|entry: &&ExtractedEntry| entry.name == "BrotliDriver")
        .expect("persist recovered Brotli driver");
    let disk_path: &std::path::PathBuf = driver.disk_path.as_ref().expect("recovered driver path");
    assert_eq!(
        std::fs::read(disk_path).expect("read recovered Brotli driver"),
        HELLO_A_EFI
    );
}

#[test]
fn current_edk2_tiano_guided_firmware_recovers_its_only_driver_byte_for_byte() {
    assert!(
        !TIANO_GUIDED_FV
            .windows(HELLO_B_EFI.len())
            .any(|window: &[u8]| window == HELLO_B_EFI),
        "the firmware fixture must not contain an uncompressed copy of the reference image"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-uefi-fv-tiano-dispatch")
            .expect("create scratch directory");
    let out_dir: std::path::PathBuf = scratch.path().join("out");
    let result: ExtractionResult = detect_and_extract_with_hint(TIANO_GUIDED_FV, None, &out_dir)
        .expect("decode Tiano-guided firmware");
    assert_eq!(result.kind, ContainerKind::UefiFv);

    let driver: &ExtractedEntry = result
        .entries
        .iter()
        .find(|entry: &&ExtractedEntry| entry.name == "TianoDriver")
        .expect("persist recovered Tiano driver");
    let disk_path: &std::path::PathBuf = driver.disk_path.as_ref().expect("recovered driver path");
    assert_eq!(
        std::fs::read(disk_path).expect("read recovered Tiano driver"),
        HELLO_B_EFI
    );
}
