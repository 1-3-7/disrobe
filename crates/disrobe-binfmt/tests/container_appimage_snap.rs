#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_binfmt::containers::appimage::{AppImageLayout, parse_appimage};
use disrobe_binfmt::containers::snap::detect_snap;
use disrobe_binfmt::containers::squashfs::{SQUASHFS_MAGIC_LE, SUPERBLOCK_MIN_BYTES};

fn synth_appimage(offset: usize) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0u8; offset + SUPERBLOCK_MIN_BYTES + 64];
    out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    out[8..11].copy_from_slice(&[b'A', b'I', 0x02]);
    out[offset..offset + 4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
    out[offset + 20..offset + 22].copy_from_slice(&6u16.to_le_bytes());
    out[offset + 28..offset + 30].copy_from_slice(&4u16.to_le_bytes());
    out
}

#[test]
fn appimage_layout_recovered_from_synthetic_binary() {
    let bytes: Vec<u8> = synth_appimage(0x10_000);
    let layout: AppImageLayout = parse_appimage(&bytes).expect("parse appimage");
    assert!(layout.elf_present);
    assert!(layout.appimage_magic_present);
    assert_eq!(layout.squashfs_offset, 0x10_000);
}

#[test]
fn snap_detector_returns_some_for_squashfs_at_offset_zero() {
    let mut bytes: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES + 32];
    bytes[0..4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
    bytes[20..22].copy_from_slice(&4u16.to_le_bytes());
    bytes[28..30].copy_from_slice(&4u16.to_le_bytes());
    let parsed: Option<disrobe_binfmt::containers::squashfs::SquashfsSuperblock> =
        detect_snap(&bytes);
    assert!(parsed.is_some());
}
