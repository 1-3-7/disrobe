#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_binfmt::containers::appimage::{AppImageLayout, parse_appimage};
use disrobe_binfmt::containers::squashfs::SquashfsCompression;

const FORMAT_DIR: &str = "appimage";
const FIXTURE_NAME: &str = "hello.AppImage";

#[test]
fn real_appimage_layout_recovered() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} — see corpus/binfmt/MANIFEST.toml for regeneration"
        );
    };
    assert!(bytes.len() > 1_000_000);
    let layout: AppImageLayout = parse_appimage(&bytes).expect("parse appimage");
    assert!(layout.elf_present);
    assert!(layout.appimage_magic_present);
    assert_eq!(layout.squashfs_offset, 0x10_000);
    assert_eq!(layout.superblock.version_major, 4);
    assert!(matches!(
        layout.superblock.compression,
        SquashfsCompression::Xz
    ));
    assert!(layout.superblock.inode_count > 100);
}

#[test]
fn real_appimage_elf_header_bytes() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    assert_eq!(&bytes[0..4], b"\x7fELF");
    assert_eq!(&bytes[8..11], b"AI\x02");
}
