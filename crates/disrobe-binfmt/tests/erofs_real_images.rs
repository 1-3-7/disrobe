#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest, Sha256};

const LZMA_FULL_BIG_XATTR: &[u8] = include_bytes!("fixtures/erofs/lzma-full-big-xattr.erofs");
const IMAGE_SHA256: &str = "82889600a82a9eb91e9ccd79c6267b7d8d40becce73f7841cf65d372b325ce02";
const PAYLOAD_SHA256: &str = "e7807e2e9a4b306c2c83d38059553aa2f67bc5aeec0ea2f8594adf5a634070b6";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn real_mkfs_lzma_full_index_extracts_byte_exact() {
    assert_eq!(digest(LZMA_FULL_BIG_XATTR), IMAGE_SHA256);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-erofs-lzma")
            .expect("create scratch directory");
    let output: PathBuf = scratch.path().to_path_buf();

    let result: ExtractionResult = extract_to(ContainerKind::Erofs, LZMA_FULL_BIG_XATTR, &output)
        .expect("extract official lzma erofs image");
    assert!(
        result.integrity_violations.is_empty(),
        "{:?}",
        result.integrity_violations
    );
    let recovered: Vec<u8> =
        std::fs::read(output.join("payload.txt")).expect("read recovered payload");
    assert_eq!(recovered.len(), 42_450);
    assert_eq!(digest(&recovered), PAYLOAD_SHA256);
}
