#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_binfmt::containers::cramfs::{CRAMFS_HEADER_SIZE, CRAMFS_MAGIC, detect_cramfs};
use disrobe_binfmt::containers::ext4::{EXT4_MAGIC, EXT4_SUPERBLOCK_OFFSET, detect_ext4};
use disrobe_binfmt::containers::squashfs::{
    SQUASHFS_MAGIC_LE, SUPERBLOCK_MIN_BYTES, parse_squashfs_superblock,
};

#[test]
fn cramfs_header_minimum_detection() {
    let mut bytes: Vec<u8> = vec![0u8; CRAMFS_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
    bytes[4..8].copy_from_slice(&65_536u32.to_le_bytes());
    let header: disrobe_binfmt::containers::cramfs::CramfsHeader =
        detect_cramfs(&bytes).expect("cramfs");
    assert_eq!(header.magic, CRAMFS_MAGIC);
    assert_eq!(header.size, 65_536);
}

#[test]
fn ext4_superblock_detection_at_offset_1024() {
    let mut bytes: Vec<u8> = vec![0u8; EXT4_SUPERBLOCK_OFFSET + 0x400];
    bytes[EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + 4]
        .copy_from_slice(&256u32.to_le_bytes());
    bytes[EXT4_SUPERBLOCK_OFFSET + 0x38..EXT4_SUPERBLOCK_OFFSET + 0x3A]
        .copy_from_slice(&EXT4_MAGIC.to_le_bytes());
    let sb: disrobe_binfmt::containers::ext4::Ext4SuperblockSummary =
        detect_ext4(&bytes).expect("ext4");
    assert_eq!(sb.magic, EXT4_MAGIC);
    assert_eq!(sb.inodes_count, 256);
}

#[test]
fn squashfs_superblock_pure_rust_parse() {
    let mut bytes: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
    bytes[0..4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
    bytes[20..22].copy_from_slice(&6u16.to_le_bytes());
    bytes[28..30].copy_from_slice(&4u16.to_le_bytes());
    let sb: disrobe_binfmt::containers::squashfs::SquashfsSuperblock =
        parse_squashfs_superblock(&bytes, 0).expect("superblock");
    assert_eq!(sb.version_major, 4);
}

#[test]
#[ignore = "BLOCKER: full squashfs/cramfs/ext4 filesystem walks require GPL fixture images from upstream tooling; pure-Rust extraction via backhand crate deferred to next sprint due to API stabilization (backhand 0.25 ABI churn)"]
fn squashfs_full_walk_via_backhand_fixture() {
    panic!("ignored: GPL-fixture-dependent");
}
