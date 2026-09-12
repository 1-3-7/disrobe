#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "deb";
const FIXTURE_NAME: &str = "lzma.deb";

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-deblzma-{name}");
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
fn deb_data_tar_lzma_recovers_members_byte_exact() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME).unwrap_or_else(|| {
        panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}")
    });

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("extract");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Deb, &bytes, &out).expect("extract deb with lzma data member");
    assert_eq!(result.kind, ContainerKind::Deb);
    assert!(
        result.integrity_violations.is_empty(),
        "extraction reported violations: {:?}",
        result.integrity_violations
    );

    for member in ["usr/bin/example", "etc/example/config"] {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered from {FIXTURE_NAME}; violations: {:?}",
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from data.tar.lzma must be byte-identical to the source file"
        );
    }
}
