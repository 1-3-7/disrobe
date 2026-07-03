#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use disrobe_binfmt::classify::{Action, classify_input};
use disrobe_binfmt::container::{ContainerKind, detect_container};

const ROMFS_MAGIC: &[u8; 8] = b"-rom1fs-";
const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const BTRFS_SEND_MAGIC: &[u8; 13] = b"btrfs-stream\0";
const UBI_EC_HDR_MAGIC: &[u8; 4] = b"UBI#";
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
const JFFS2_MAGIC: u16 = 0x1985;
const JFFS2_NODETYPE_INODE: u16 = 0xE002;
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

fn minimal_romfs() -> Vec<u8> {
    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(ROMFS_MAGIC);
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(b"rom");
    image.push(0);
    while !image.len().is_multiple_of(16) {
        image.push(0);
    }
    let body: &[u8] = b"hello romfs";
    let next_raw: u32 = 2;
    image.extend_from_slice(&next_raw.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(&(body.len() as u32).to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    let name: &[u8] = b"file.txt";
    image.extend_from_slice(name);
    image.push(0);
    while !image.len().is_multiple_of(16) {
        image.push(0);
    }
    image.extend_from_slice(body);
    while !image.len().is_multiple_of(16) {
        image.push(0);
    }
    let full: u32 = image.len() as u32;
    image[8..12].copy_from_slice(&full.to_be_bytes());
    image
}

fn minimal_sparse() -> Vec<u8> {
    let mut img: Vec<u8> = Vec::new();
    img.extend_from_slice(&SPARSE_MAGIC.to_le_bytes());
    img.extend_from_slice(&1u16.to_le_bytes());
    img.extend_from_slice(&0u16.to_le_bytes());
    img.extend_from_slice(&28u16.to_le_bytes());
    img.extend_from_slice(&12u16.to_le_bytes());
    img.extend_from_slice(&4096u32.to_le_bytes());
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&0u32.to_le_bytes());
    img.extend_from_slice(&0xCAC1u16.to_le_bytes());
    img.extend_from_slice(&0u16.to_le_bytes());
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&((12 + 4096) as u32).to_le_bytes());
    img.extend(std::iter::repeat_n(0x42u8, 4096));
    img
}

fn minimal_btrfs_send() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(BTRFS_SEND_MAGIC);
    out.extend_from_slice(&1u32.to_le_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&15u16.to_le_bytes());
    body.extend_from_slice(&(b"f".len() as u16).to_le_bytes());
    body.extend_from_slice(b"f");
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&21u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn minimal_ubi() -> Vec<u8> {
    const PEB: usize = 65536;
    const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;
    let mut peb: Vec<u8> = vec![0xFFu8; PEB];
    peb[0..4].copy_from_slice(UBI_EC_HDR_MAGIC);
    peb[16..20].copy_from_slice(&64u32.to_be_bytes());
    peb[20..24].copy_from_slice(&128u32.to_be_bytes());
    peb[64..68].copy_from_slice(b"UBI!");
    peb[64 + 4] = 2;
    peb[64 + 8..64 + 12].copy_from_slice(&0u32.to_be_bytes());
    peb[64 + 12..64 + 16].copy_from_slice(&0u32.to_be_bytes());
    peb[128..132].copy_from_slice(&UBIFS_NODE_MAGIC.to_le_bytes());
    peb
}

fn minimal_erofs() -> Vec<u8> {
    const BLK: usize = 4096;
    let mut image: Vec<u8> = vec![0u8; 8 * BLK];
    let base: usize = 1024;
    image[base..base + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
    image[base + 12] = 12;
    image[base + 16..base + 18].copy_from_slice(&0u16.to_le_bytes());
    image[base + 36..base + 40].copy_from_slice(&2u32.to_le_bytes());
    let meta: usize = 2 * BLK;
    let format: u16 = 0;
    image[meta..meta + 2].copy_from_slice(&format.to_le_bytes());
    let dir_mode: u16 = 0o040_000 | 0o755;
    image[meta + 4..meta + 6].copy_from_slice(&dir_mode.to_le_bytes());
    image[meta + 8..meta + 12].copy_from_slice(&0u32.to_le_bytes());
    image
}

fn minimal_jffs2() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let body: Vec<u8> = b"jffs2 detect".to_vec();
    let mut node: Vec<u8> = Vec::new();
    node.extend_from_slice(&JFFS2_MAGIC.to_le_bytes());
    node.extend_from_slice(&JFFS2_NODETYPE_INODE.to_le_bytes());
    let totlen: u32 = (68 + body.len()) as u32;
    node.extend_from_slice(&totlen.to_le_bytes());
    node.extend_from_slice(&0u32.to_le_bytes());
    node.resize(68, 0);
    node[12..16].copy_from_slice(&2u32.to_le_bytes());
    node[16..20].copy_from_slice(&1u32.to_le_bytes());
    node[20..24].copy_from_slice(&(0o100_000u32 | 0o644).to_le_bytes());
    node[28..32].copy_from_slice(&(body.len() as u32).to_le_bytes());
    node[48..52].copy_from_slice(&(body.len() as u32).to_le_bytes());
    node[52..56].copy_from_slice(&(body.len() as u32).to_le_bytes());
    node.extend_from_slice(&body);
    out.extend_from_slice(&node);
    out
}

fn minimal_ntfs() -> Vec<u8> {
    let mut boot: Vec<u8> = vec![0u8; 512];
    boot[3..11].copy_from_slice(NTFS_OEM_ID);
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 8;
    boot
}

fn assert_routes_to(bytes: &[u8], expected: ContainerKind, name: &str) {
    let detected: Option<ContainerKind> = detect_container(bytes);
    assert_eq!(
        detected,
        Some(expected),
        "{name}: detect_container mismatch"
    );
    let cl = classify_input(Path::new(name), bytes);
    match cl.primary_action {
        Action::ExtractArchive { container } => {
            assert_eq!(container, expected, "{name}: classify routed to wrong kind");
        }
        other => panic!("{name}: expected ExtractArchive, got {other:?}"),
    }
}

#[test]
fn romfs_detects_and_routes() {
    assert_routes_to(&minimal_romfs(), ContainerKind::Romfs, "image.romfs");
}

#[test]
fn android_sparse_detects_and_routes() {
    assert_routes_to(
        &minimal_sparse(),
        ContainerKind::AndroidSparse,
        "system.img",
    );
}

#[test]
fn btrfs_send_detects_and_routes() {
    assert_routes_to(
        &minimal_btrfs_send(),
        ContainerKind::BtrfsSend,
        "snapshot.send",
    );
}

#[test]
fn ubi_detects_and_routes() {
    assert_routes_to(&minimal_ubi(), ContainerKind::Ubifs, "flash.ubi");
}

#[test]
fn erofs_detects_and_routes() {
    assert_routes_to(&minimal_erofs(), ContainerKind::Erofs, "root.erofs");
}

#[test]
fn jffs2_detects_and_routes() {
    assert_routes_to(&minimal_jffs2(), ContainerKind::Jffs2, "rootfs.jffs2");
}

#[test]
fn ntfs_detects_and_routes() {
    assert_routes_to(&minimal_ntfs(), ContainerKind::Ntfs, "disk.ntfs");
}

#[test]
fn ntfs_does_not_collide_with_fat() {
    let ntfs: Vec<u8> = minimal_ntfs();
    assert_ne!(detect_container(&ntfs), Some(ContainerKind::Fat));
    assert_eq!(detect_container(&ntfs), Some(ContainerKind::Ntfs));
}

#[test]
fn new_kinds_are_payload_extractors() {
    for kind in [
        ContainerKind::Romfs,
        ContainerKind::MinixFs,
        ContainerKind::AndroidSparse,
        ContainerKind::BtrfsSend,
        ContainerKind::Erofs,
        ContainerKind::Jffs2,
        ContainerKind::Ntfs,
        ContainerKind::Ubifs,
        ContainerKind::Yaffs2,
    ] {
        assert_eq!(
            kind.extraction_mode(),
            disrobe_binfmt::container::ExtractionMode::Payload,
            "{kind:?} must be a payload extractor"
        );
    }
}
