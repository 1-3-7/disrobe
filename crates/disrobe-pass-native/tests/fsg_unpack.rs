#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod packer_fixture;

use disrobe_pass_native::error::Error;
use disrobe_pass_native::packers::{FsgUnpackOutput, unpack_fsg};
use packer_fixture::{PackerFixture, load_fixture};

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder: "FSG",
        family: "fsg",
        name,
    })
}

fn expect_fsg_anchors(out: &FsgUnpackOutput) {
    assert!(
        out.image_base == 0x0040_0000 || out.image_base == 0x0100_0000,
        "unexpected ImageBase 0x{:08X}",
        out.image_base
    );
    assert!(
        out.unpack_dest_va >= out.image_base,
        "unpack_dest_va must be inside image"
    );
    assert!(
        out.packed_stream_va >= out.image_base,
        "packed stream VA must be inside image"
    );
    assert!(
        out.import_meta_va >= out.image_base,
        "import-meta VA must be inside image"
    );
    assert!(
        !out.raw_image.is_empty(),
        "decompressed image must be non-empty"
    );
    assert!(
        out.raw_image.len() >= 0x1000,
        "decompressed image must be at least one page (got {} bytes)",
        out.raw_image.len()
    );
}

#[test]
fn test_fsg_aatools_setup_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_hash_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("Hash.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_ftp_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("ftp.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_rejects_non_fsg_pe() {
    let mut bytes: Vec<u8> = vec![0u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0xC0u32.to_le_bytes());
    bytes[0xC0..0xC4].copy_from_slice(b"PE\0\0");
    bytes[0xC4..0xC6].copy_from_slice(&0x014Cu16.to_le_bytes());
    bytes[0xC6..0xC8].copy_from_slice(&1u16.to_le_bytes());
    bytes[0xD8..0xDA].copy_from_slice(&0xE0u16.to_le_bytes());
    bytes[0xDC..0xDE].copy_from_slice(&0x010Bu16.to_le_bytes());
    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&bytes);
    assert!(r.is_err(), "non-FSG PE must not unpack");
}

#[test]
fn test_fsg_unpacked_pe_runs_structural_check() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
    let starts_with_code: bool = out.raw_image.first().is_some_and(|&b: &u8| b != 0x00);
    assert!(
        starts_with_code,
        "first byte of unpacked image should not be NUL (would indicate bss-only output)"
    );
}

#[test]
fn test_fsg_synthetic_truncated_stream_errors_cleanly() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        return;
    };
    let truncated: Vec<u8> = packed[..0x250].to_vec();
    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&truncated);
    assert!(r.is_err(), "truncated stream must error, not panic or hang");
}
