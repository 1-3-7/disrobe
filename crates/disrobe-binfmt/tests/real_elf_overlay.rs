#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::containers::{ElfOverlayCarve, carve_elf_overlay};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "elf-overlay";

fn temp_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-elfoverlay-{tag}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
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

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("cpio");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Cpio, overlay, &out).expect("extract carved cpio");
    assert_eq!(result.kind, ContainerKind::Cpio);
    let got: Vec<u8> = std::fs::read(out.join("init.txt")).expect("recovered init.txt");
    assert_eq!(got, want, "initramfs member must be byte-identical");
}

#[test]
fn a_newc_trailer_with_a_nonstandard_header_width_is_refused() {
    let malformed: Vec<u8> = common::load_fixture(FORMAT_DIR, "cpio-malformed-trailer.bin")
        .expect("cpio-malformed-trailer.bin");
    let valid: Vec<u8> = common::load_fixture(FORMAT_DIR, "cpio.bin").expect("cpio.bin");
    assert_eq!(
        malformed.len(),
        valid.len(),
        "the two fixtures differ in their trailer layout, not in size"
    );
    assert_eq!(
        malformed[..420],
        valid[..420],
        "both fixtures must carry the identical well-formed first member, so the refusal below \
         is attributable to the trailer alone"
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("cpio-malformed");
    let out: PathBuf = scratch.path().to_path_buf();
    let error: disrobe_binfmt::Error = extract_to(ContainerKind::Cpio, &malformed, &out)
        .expect_err("a newc trailer whose name sits 126 bytes after its header must be refused");
    let text: String = error.to_string();
    assert!(
        text.contains("zero-length name"),
        "the refusal must name the field it actually read, got {text}"
    );
    assert!(
        text.contains("420"),
        "the refusal must name the offset it failed at, got {text}"
    );
    assert_eq!(
        std::fs::read_dir(&out)
            .expect("read refusal output directory")
            .count(),
        0,
        "a refused archive must publish no member, not even the well-formed first one"
    );
}
