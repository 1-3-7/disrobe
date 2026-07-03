#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::containers::squashfs::{
    SQUASHFS_MAGIC_LE, SquashfsCompression, SquashfsSuperblock, parse_squashfs_superblock,
};

const FORMAT_DIR: &str = "squashfs";
const FIXTURE_NAME: &str = "hello.squashfs";

#[test]
#[ignore = "needs gitignored real fixture corpus/binfmt/squashfs/hello.squashfs (mksquashfs, ~5MB); regen via corpus/binfmt/MANIFEST.toml, run with --ignored"]
fn real_squashfs_superblock_parses() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} - see corpus/binfmt/MANIFEST.toml for regeneration"
        );
    };
    assert!(
        bytes.len() > 1_000_000,
        "fixture too small: {}",
        bytes.len()
    );
    let sb: SquashfsSuperblock =
        parse_squashfs_superblock(&bytes, 0).expect("parse real squashfs superblock");
    assert_eq!(sb.version_major, 4);
    assert!(sb.little_endian);
    assert!(matches!(sb.compression, SquashfsCompression::Xz));
    assert!(
        sb.inode_count > 100,
        "expected 100+ inodes, got {}",
        sb.inode_count
    );
    assert_eq!(sb.block_size, 131_072);
}

#[test]
#[ignore = "needs gitignored real fixture corpus/binfmt/squashfs/hello.squashfs (mksquashfs, ~5MB); regen via corpus/binfmt/MANIFEST.toml, run with --ignored"]
fn real_squashfs_starts_with_le_magic() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    let head_magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(head_magic, SQUASHFS_MAGIC_LE);
}

#[test]
#[ignore = "needs gitignored real fixture corpus/binfmt/squashfs/hello.squashfs (mksquashfs, ~5MB); regen via corpus/binfmt/MANIFEST.toml, run with --ignored"]
fn real_squashfs_records_payload_byte_count() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    let sb: SquashfsSuperblock =
        parse_squashfs_superblock(&bytes, 0).expect("parse real squashfs superblock");
    assert!(sb.bytes_used > 4_000_000, "bytes_used = {}", sb.bytes_used);
    assert!(
        sb.bytes_used <= bytes.len() as u64,
        "superblock bytes_used {} exceeds file size {}",
        sb.bytes_used,
        bytes.len()
    );
}
