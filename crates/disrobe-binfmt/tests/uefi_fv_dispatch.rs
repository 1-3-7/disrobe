#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_binfmt::{
    ContainerKind, ExtractedEntry, ExtractionResult, detect_and_extract_with_hint, detect_container,
};

const OUTER_FV: &[u8] = include_bytes!("fixtures/uefi_fv/outer.fv");
const HELLO_A_EFI: &[u8] = include_bytes!("fixtures/uefi_fv/hello_a.efi");

#[test]
fn auto_detect_classifies_a_real_edk2_built_firmware_volume_as_uefi_fv() {
    let kind: ContainerKind = detect_container(OUTER_FV).expect("detected");
    assert_eq!(kind, ContainerKind::UefiFv);
}

#[test]
fn top_level_detect_and_extract_recovers_the_driver_pe_without_calling_uefi_fv_directly() {
    let out_dir: std::path::PathBuf =
        std::env::temp_dir().join(format!("disrobe-uefi-fv-dispatch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);

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

    let summary_path: std::path::PathBuf = out_dir.join(".disrobe-uefi-fv.json");
    assert!(summary_path.exists());

    let _ = std::fs::remove_dir_all(&out_dir);
}
