#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "uzip";

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-uzip-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn expected_image() -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FORMAT_DIR)
        .join("expected")
        .join("uzip.img");
    std::fs::read(&path).expect("read ground-truth uzip/expected/uzip.img")
}

fn run_case(fixture: &str) {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, fixture).unwrap_or_else(|| {
        panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/{fixture}")
    });

    assert_eq!(detect_container(&bytes), Some(ContainerKind::Uzip));

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(fixture);

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Uzip, &bytes, &out).expect("extract uzip");
    assert_eq!(result.kind, ContainerKind::Uzip);

    let want: Vec<u8> = expected_image();
    let got: Vec<u8> = std::fs::read(out.join("uzip.img")).expect("recovered uzip.img");
    assert_eq!(
        got, want,
        "reconstructed UZIP disk image from {fixture} must be byte-identical to the source blocks"
    );
}

#[test]
fn uzip_zlib_blocks_reconstruct_byte_exact() {
    run_case("hello-zlib.uzip");
}

#[test]
fn uzip_lzma_blocks_reconstruct_byte_exact() {
    run_case("hello-lzma.uzip");
}
