#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "xalz";
const FIXTURE_NAME: &str = "hello.dll.xalz";

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-xalz-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FORMAT_DIR)
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth {FORMAT_DIR}/expected/{rel}"))
}

#[test]
fn xalz_detects_and_decodes_managed_assembly_byte_exact() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME).unwrap_or_else(|| {
        panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}")
    });

    assert_eq!(detect_container(&bytes), Some(ContainerKind::Xalz));

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("extract");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Xalz, &bytes, &out).expect("extract xalz");
    assert_eq!(result.kind, ContainerKind::Xalz);
    assert!(
        result.integrity_violations.is_empty(),
        "violations: {:?}",
        result.integrity_violations
    );

    let want: Vec<u8> = expected_bytes("assembly.dll");
    let got: Vec<u8> = std::fs::read(out.join("assembly.dll")).expect("recovered assembly.dll");
    assert_eq!(
        got, want,
        "XALZ-decompressed .NET assembly must be byte-identical to the source (real lz4.block oracle)"
    );
}
