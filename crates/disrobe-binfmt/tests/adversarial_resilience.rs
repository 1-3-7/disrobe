#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_binfmt::containers::ext4::walk_ext4;
use disrobe_binfmt::containers::fat::{detect_fat, walk_fat};
use disrobe_binfmt::containers::vhd::parse_vhd;
use disrobe_binfmt::containers::vhdx::parse_vhdx;
use disrobe_binfmt::containers::wim::parse_wim_header;
use disrobe_binfmt::{ContainerKind, Error, detect_container, extract_to};

const BS: usize = 1024;
const INODE_SIZE: usize = 128;
const INODES_PER_GROUP: u32 = 16;
const EXT4_SB_OFFSET: usize = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;
const EXT4_ROOT_INODE: u32 = 2;

fn extent_inode(
    mode: u16,
    size: u32,
    logical_block: u32,
    phys_block: u32,
    block_count: u16,
) -> [u8; INODE_SIZE] {
    let mut raw: [u8; INODE_SIZE] = [0u8; INODE_SIZE];
    raw[0x0..0x2].copy_from_slice(&mode.to_le_bytes());
    raw[0x4..0x8].copy_from_slice(&size.to_le_bytes());
    raw[0x20..0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    let ib: &mut [u8] = &mut raw[0x28..0x28 + 60];
    ib[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
    ib[2..4].copy_from_slice(&1u16.to_le_bytes());
    ib[4..6].copy_from_slice(&4u16.to_le_bytes());
    ib[6..8].copy_from_slice(&0u16.to_le_bytes());
    ib[12..16].copy_from_slice(&logical_block.to_le_bytes());
    ib[16..18].copy_from_slice(&block_count.to_le_bytes());
    ib[18..20].copy_from_slice(&0u16.to_le_bytes());
    ib[20..24].copy_from_slice(&phys_block.to_le_bytes());
    raw
}

fn dir_entry(out: &mut Vec<u8>, ino: u32, name: &str, file_type: u8, rec_len: u16) {
    let start: usize = out.len();
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&rec_len.to_le_bytes());
    out.push(name.len() as u8);
    out.push(file_type);
    out.extend_from_slice(name.as_bytes());
    out.resize(start + rec_len as usize, 0);
}

fn build_ext4_with_file_extent(logical_block: u32) -> Vec<u8> {
    let total_blocks: usize = 16;
    let mut image: Vec<u8> = vec![0u8; total_blocks * BS];

    image[EXT4_SB_OFFSET..EXT4_SB_OFFSET + 4].copy_from_slice(&64u32.to_le_bytes());
    image[EXT4_SB_OFFSET + 4..EXT4_SB_OFFSET + 8]
        .copy_from_slice(&(total_blocks as u32).to_le_bytes());
    image[EXT4_SB_OFFSET + 0x14..EXT4_SB_OFFSET + 0x18].copy_from_slice(&1u32.to_le_bytes());
    image[EXT4_SB_OFFSET + 0x18..EXT4_SB_OFFSET + 0x1C].copy_from_slice(&0u32.to_le_bytes());
    image[EXT4_SB_OFFSET + 0x28..EXT4_SB_OFFSET + 0x2C]
        .copy_from_slice(&INODES_PER_GROUP.to_le_bytes());
    image[EXT4_SB_OFFSET + 0x38..EXT4_SB_OFFSET + 0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
    image[EXT4_SB_OFFSET + 0x58..EXT4_SB_OFFSET + 0x5A]
        .copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());

    let gdt_off: usize = 2 * BS;
    let inode_table_block: u32 = 3;
    image[gdt_off + 0x8..gdt_off + 0xC].copy_from_slice(&inode_table_block.to_le_bytes());

    let inode_table_off: usize = inode_table_block as usize * BS;
    let root_data_block: u32 = 5;
    let file_data_block: u32 = 6;
    let file_ino: u32 = 11;

    let root_inode: [u8; INODE_SIZE] =
        extent_inode(S_IFDIR | 0o755, BS as u32, 0, root_data_block, 1);
    let root_off: usize = inode_table_off + (EXT4_ROOT_INODE as usize - 1) * INODE_SIZE;
    image[root_off..root_off + INODE_SIZE].copy_from_slice(&root_inode);

    let file_inode: [u8; INODE_SIZE] =
        extent_inode(S_IFREG | 0o644, 64, logical_block, file_data_block, 1);
    let file_inode_off: usize = inode_table_off + (file_ino as usize - 1) * INODE_SIZE;
    image[file_inode_off..file_inode_off + INODE_SIZE].copy_from_slice(&file_inode);

    let mut dir: Vec<u8> = Vec::new();
    dir_entry(&mut dir, EXT4_ROOT_INODE, ".", 2, 12);
    dir_entry(&mut dir, EXT4_ROOT_INODE, "..", 2, 12);
    dir_entry(&mut dir, file_ino, "bomb.bin", 1, (BS as u16) - 24);
    let root_data_off: usize = root_data_block as usize * BS;
    image[root_data_off..root_data_off + dir.len().min(BS)]
        .copy_from_slice(&dir[..dir.len().min(BS)]);

    image
}

#[test]
fn ext4_extent_logical_offset_bomb_is_rejected_not_oom() {
    let cap: u64 = 64 * 1024 * 1024;
    let image: Vec<u8> = build_ext4_with_file_extent(0x1000_0000);
    let err: Error = walk_ext4(&image, cap)
        .expect_err("256 GiB logical offset over a 64 MiB cap must be rejected, not resized");
    let Error::Ext4(reason) = err else {
        panic!("logical-offset bomb must fail as Error::Ext4, got {err:?}");
    };
    assert_eq!(
        reason, "ext4 extent logical offset exceeds total cap",
        "the rejection must name the logical-offset-over-cap guard, not some unrelated parse failure"
    );
}

#[test]
fn ext4_benign_extent_still_walks() {
    let image: Vec<u8> = build_ext4_with_file_extent(0);
    let walk = walk_ext4(&image, 64 * 1024 * 1024).expect("benign ext4 must still walk");
    assert!(
        walk.files.iter().any(|f| f.path == "bomb.bin"),
        "the regular file must be recovered when its extent is benign"
    );
}

#[test]
fn ext4_truncated_and_garbage_never_panic() {
    for len in [0usize, 1, 64, 512, 1024, 1500, 2048] {
        let bytes: Vec<u8> = vec![0xABu8; len];
        let _ = walk_ext4(&bytes, 1 << 20);
    }
    let mut almost: Vec<u8> = vec![0u8; EXT4_SB_OFFSET + 0x400];
    almost[EXT4_SB_OFFSET + 0x38..EXT4_SB_OFFSET + 0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
    let _ = walk_ext4(&almost, 1 << 20);
}

#[test]
fn fat_truncated_and_garbage_never_panic() {
    for len in [0usize, 1, 11, 13, 17, 64, 510, 512] {
        let mut bytes: Vec<u8> = vec![0u8; len];
        if len >= 512 {
            bytes[510] = 0x55;
            bytes[511] = 0xaa;
        }
        let _ = detect_fat(&bytes);
        let _ = walk_fat(&bytes, 1 << 20);
    }
    let mut crafted: Vec<u8> = vec![0u8; 512];
    crafted[11..13].copy_from_slice(&512u16.to_le_bytes());
    crafted[13] = 1;
    crafted[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());
    crafted[16] = 2;
    crafted[17..19].copy_from_slice(&512u16.to_le_bytes());
    crafted[19..21].copy_from_slice(&0xFFFFu16.to_le_bytes());
    crafted[22..24].copy_from_slice(&0xFFFFu16.to_le_bytes());
    crafted[510] = 0x55;
    crafted[511] = 0xaa;
    let _ = walk_fat(&crafted, 1 << 20);
}

#[test]
fn disk_image_headers_reject_truncation_without_panic() {
    for len in [0usize, 4, 16, 64, 256, 511, 512, 1024] {
        let bytes: Vec<u8> = vec![0x00u8; len];
        let _ = parse_vhd(&bytes);
        let _ = parse_vhdx(&bytes);
        let _ = parse_wim_header(&bytes);
        let mut signed: Vec<u8> = bytes.clone();
        if signed.len() >= 8 {
            signed[0..8].copy_from_slice(b"conectix");
        }
        let _ = parse_vhd(&signed);
    }
}

#[test]
fn wim_header_oversized_resource_size_does_not_oom() {
    let mut bytes: Vec<u8> = vec![0u8; 208];
    bytes[0..8].copy_from_slice(b"MSWIM\x00\x00\x00");
    bytes[8..12].copy_from_slice(&208u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&0x0001_0d00_u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&0x0000_0002_u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let _ = parse_wim_header(&bytes);
}

#[test]
fn detector_never_panics_on_hostile_byte_patterns() {
    let seeds: [&[u8]; 12] = [
        b"PK\x03\x04",
        b"Rar!\x1a\x07\x00",
        b"Rar!\x1a\x07\x01\x00",
        b"MSCF",
        b"7z\xbc\xaf\x27\x1c",
        b"conectix",
        b"vhdxfile",
        b"MSWIM\x00\x00\x00",
        b"EFI PART",
        b"\x1f\x8b\x08",
        b"\xfd7zXZ\x00",
        b"ustar\x0000",
    ];
    for seed in seeds {
        for trunc in 0..=seed.len() {
            let _ = detect_container(&seed[..trunc]);
        }
        let mut padded: Vec<u8> = seed.to_vec();
        padded.resize(70_000, 0u8);
        let _ = detect_container(&padded);
        let mut tail: Vec<u8> = vec![0u8; 40_000];
        tail.extend_from_slice(seed);
        let _ = detect_container(&tail);
    }
    for len in [0usize, 1, 2, 3, 7, 15, 511, 512, 1023, 1024, 32_769, 33_000] {
        let zeros: Vec<u8> = vec![0u8; len];
        let _ = detect_container(&zeros);
        let ones: Vec<u8> = vec![0xFFu8; len];
        let _ = detect_container(&ones);
    }
}

#[test]
fn extract_rejects_unsupported_or_garbage_without_panic() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-adv-extract")
            .expect("create scratch directory");
    let dir: PathBuf = scratch.path().join("out");
    let garbage: Vec<u8> = vec![0x41u8; 4096];
    for kind in [
        ContainerKind::Zip,
        ContainerKind::Rar,
        ContainerKind::Cab,
        ContainerKind::SevenZ,
        ContainerKind::Tar,
        ContainerKind::Wim,
        ContainerKind::Vhd,
        ContainerKind::Vhdx,
    ] {
        let _ = extract_to(kind, &garbage, &dir);
        let _ = extract_to(kind, &[], &dir);
    }
}
