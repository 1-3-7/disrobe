#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Packer, detect_packers, packed_upx_elf64_marker};

#[test]
fn baked_upx_elf64_marker_detected() {
    let bytes: Vec<u8> = packed_upx_elf64_marker();
    let hits = detect_packers(&bytes);
    assert!(hits.iter().any(|h| h.packer == Packer::Upx));
}

#[test]
#[ignore = "FIXTURE PENDING: real UPX-packed PE/ELF/Mach-O across LZMA + zstd variants required"]
fn real_upx_lzma_and_zstd_variants_unpack() {}
