#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest, Sha256};

const LZMA_FULL_BIG_XATTR: &[u8] = include_bytes!("fixtures/erofs/lzma-full-big-xattr.erofs");
const LZMA_COMPACT_BIG_XATTR: &[u8] = include_bytes!("fixtures/erofs/lzma-compact-big-xattr.erofs");
const LZMA_COMPACT_MIXED: &[u8] = include_bytes!("fixtures/erofs/lzma-compact-mixed.erofs");
const FULL_IMAGE_SHA256: &str = "82889600a82a9eb91e9ccd79c6267b7d8d40becce73f7841cf65d372b325ce02";
const COMPACT_IMAGE_SHA256: &str =
    "472b4cbc1e3cf2f59de0c55a9b3ef1cb9182e316b529718be8b64c4d559c4552";
const COMPACT_MIXED_IMAGE_SHA256: &str =
    "95f21754692944b7a7f91a91402e8dfa133860f5fb2082ab7a1178bd55c1bb77";
const PAYLOAD_SHA256: &str = "e7807e2e9a4b306c2c83d38059553aa2f67bc5aeec0ea2f8594adf5a634070b6";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn real_mkfs_lzma_full_index_extracts_byte_exact() {
    assert_eq!(digest(LZMA_FULL_BIG_XATTR), FULL_IMAGE_SHA256);
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

#[test]
fn real_mkfs_lzma_compact_index_matches_full_index_bytes() {
    assert_eq!(digest(LZMA_COMPACT_BIG_XATTR), COMPACT_IMAGE_SHA256);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-erofs-lzma-compact")
            .expect("create scratch directory");
    let output: PathBuf = scratch.path().to_path_buf();

    let result: ExtractionResult =
        extract_to(ContainerKind::Erofs, LZMA_COMPACT_BIG_XATTR, &output)
            .expect("extract official compact-index lzma erofs image");
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

#[test]
fn real_mkfs_lzma_mixed_compact_packs_extract_byte_exact() {
    assert_eq!(digest(LZMA_COMPACT_MIXED), COMPACT_MIXED_IMAGE_SHA256);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-erofs-lzma-compact-mixed")
            .expect("create scratch directory");
    let output: PathBuf = scratch.path().to_path_buf();

    let result: ExtractionResult = extract_to(ContainerKind::Erofs, LZMA_COMPACT_MIXED, &output)
        .expect("extract official mixed compact-index lzma erofs image");
    assert!(
        result.integrity_violations.is_empty(),
        "{:?}",
        result.integrity_violations
    );
    let recovered: Vec<u8> =
        std::fs::read(output.join("payload.txt")).expect("read recovered mixed-pack payload");
    assert_eq!(recovered.len(), 212_250);
    assert_eq!(
        digest(&recovered),
        "ff288b1f999038b715ef29b34313251f031250e6f2ad2a0cf4291d832f6b1b20"
    );
}
