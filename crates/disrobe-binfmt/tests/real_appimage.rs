#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::containers::appimage::{
    AppImageFormat, AppImageLayout, AppImagePayloadLayout, parse_appimage,
};
use disrobe_binfmt::containers::squashfs::SquashfsCompression;

const FORMAT_DIR: &str = "appimage";
const FIXTURE_NAME: &str = "hello.AppImage";
const GRADED: &str = "the real AppImage layout checks";

#[test]
fn real_appimage_layout_recovered() {
    let Some(bytes): Option<Vec<u8>> =
        common::requirement::regenerable_fixture(FORMAT_DIR, FIXTURE_NAME, GRADED)
    else {
        return;
    };
    assert!(bytes.len() > 1_000_000);
    let layout: AppImageLayout = parse_appimage(&bytes).expect("parse appimage");
    assert_eq!(layout.format, AppImageFormat::Type2);
    let AppImagePayloadLayout::Squashfs { offset, superblock } = layout.payload else {
        panic!("type 2 payload was not squashfs");
    };
    assert_eq!(offset, 0x10_000);
    assert_eq!(superblock.version_major, 4);
    assert!(matches!(superblock.compression, SquashfsCompression::Xz));
    assert!(superblock.inode_count > 100);
}

#[test]
fn real_appimage_elf_header_bytes() {
    let Some(bytes): Option<Vec<u8>> =
        common::requirement::regenerable_fixture(FORMAT_DIR, FIXTURE_NAME, GRADED)
    else {
        return;
    };
    assert_eq!(&bytes[0..4], b"\x7fELF");
    assert_eq!(&bytes[8..11], b"AI\x02");
}
