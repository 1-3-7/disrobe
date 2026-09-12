#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::rcpp::{NativeImageFormat, scan_native_images};

const REAL_ELF: &[u8] = include_bytes!("fixtures/rcpp_real.o");
const REAL_PE: &[u8] = include_bytes!("fixtures/rcpp_real.dll");

const REAL_ELF_DISK_SIZE: usize = 1224;

fn trailing_rds_junk() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"\x00\x00\x04\x02");
    v.extend_from_slice(b"names");
    v.extend_from_slice(&[0u8; 32]);
    v
}

#[test]
fn elf_extent_matches_real_on_disk_size_not_eof() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"pre\x00");
    let off: usize = blob.len();
    blob.extend_from_slice(REAL_ELF);
    blob.extend_from_slice(&trailing_rds_junk());

    let images: Vec<_> = scan_native_images(&blob);
    let elf: &_ = images
        .iter()
        .find(|i| i.format == NativeImageFormat::Elf)
        .expect("real ELF must be carved");
    assert_eq!(elf.offset, off);
    assert_eq!(
        elf.length, REAL_ELF_DISK_SIZE,
        "carved ELF length must equal the readelf-verified on-disk size, not run to blob EOF"
    );
    assert_eq!(elf.bytes.len(), REAL_ELF_DISK_SIZE);
    assert_eq!(&elf.bytes[..4], &[0x7f, b'E', b'L', b'F']);
    assert!(
        elf.length < blob.len() - off,
        "trailing RDS bytes must NOT be swallowed into the carved image"
    );
}

#[test]
fn two_concatenated_images_do_not_overlap() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(REAL_ELF);
    let second_off: usize = blob.len();
    blob.extend_from_slice(REAL_PE);

    let images: Vec<_> = scan_native_images(&blob);
    let first: &_ = images
        .iter()
        .find(|i| i.offset == 0 && i.format == NativeImageFormat::Elf)
        .expect("first ELF must be carved");
    assert!(
        first.length <= second_off,
        "first image (len {}) must end at or before the second image start ({second_off})",
        first.length
    );
    assert_eq!(
        first.length, REAL_ELF_DISK_SIZE,
        "first image bounded to its real size"
    );
    assert!(
        images
            .iter()
            .any(|i| i.offset == second_off && i.format == NativeImageFormat::Pe),
        "second image (PE) must be carved as its own distinct image"
    );
}

#[test]
fn pe_extent_does_not_run_to_eof_with_trailing_bytes() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(REAL_PE);
    let pe_only_len: usize = blob.len();
    blob.extend_from_slice(&[0xCDu8; 4096]);

    let images: Vec<_> = scan_native_images(&blob);
    let pe: &_ = images
        .iter()
        .find(|i| i.offset == 0 && i.format == NativeImageFormat::Pe)
        .expect("real PE must be carved");
    assert!(
        pe.length <= pe_only_len,
        "PE extent ({}) must not exceed the real image size ({pe_only_len})",
        pe.length
    );
    assert!(
        pe.length < blob.len(),
        "trailing 0xCD padding must NOT be swallowed into the carved PE"
    );
}
