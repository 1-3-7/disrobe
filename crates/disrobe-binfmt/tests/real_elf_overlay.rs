#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::containers::{ElfOverlayCarve, carve_elf_overlay};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "elf-overlay";

fn temp_dir(tag: &str) -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-elfoverlay-{}-{tag}", std::process::id()));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn elf_overlay_locates_appended_cpio_extent() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, "hello.elf")
        .unwrap_or_else(|| panic!("missing fixture corpus/binfmt/{FORMAT_DIR}/hello.elf"));
    let cpio: Vec<u8> = common::load_fixture(FORMAT_DIR, "cpio.bin").expect("cpio.bin");

    let carve: ElfOverlayCarve = carve_elf_overlay(&bytes).expect("carve elf overlay");
    let start: usize = carve.overlay.overlay_start as usize;
    assert_eq!(
        carve.overlay.overlay_len as usize,
        cpio.len(),
        "overlay extent must equal the appended cpio length"
    );
    assert_eq!(
        &bytes[start..start + cpio.len()],
        cpio.as_slice(),
        "carved overlay bytes must be the appended cpio verbatim"
    );
    assert_eq!(carve.appended_kind, Some(ContainerKind::Cpio));
}

#[test]
fn elf_overlay_cpio_extracts_member_byte_exact() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, "hello.elf").unwrap();
    let want: Vec<u8> =
        common::load_fixture(FORMAT_DIR, "expected/init.txt").expect("expected init.txt");

    let carve: ElfOverlayCarve = carve_elf_overlay(&bytes).expect("carve");
    let start: usize = carve.overlay.overlay_start as usize;
    let overlay: &[u8] = &bytes[start..];

    let out: PathBuf = temp_dir("cpio");
    let result: ExtractionResult =
        extract_to(ContainerKind::Cpio, overlay, &out).expect("extract carved cpio");
    assert_eq!(result.kind, ContainerKind::Cpio);
    let got: Vec<u8> = std::fs::read(out.join("init.txt")).expect("recovered init.txt");
    assert_eq!(got, want, "initramfs member must be byte-identical");
}
