#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_binfmt::containers::appimage::{
    AppImageFormat, AppImageLayout, AppImagePayloadLayout, parse_appimage,
};
use disrobe_binfmt::containers::snap::detect_snap;
use disrobe_binfmt::containers::squashfs::{
    SQUASHFS_MAGIC_LE, SUPERBLOCK_MIN_BYTES, SquashfsCompression, SquashfsSuperblock,
};

const INODE_COUNT_OFFSET: usize = 4;

const BLOCK_SIZE_OFFSET: usize = 12;

const FRAGMENT_COUNT_OFFSET: usize = 16;

const COMPRESSION_ID_OFFSET: usize = 20;

const VERSION_MAJOR_OFFSET: usize = 28;

const VERSION_MINOR_OFFSET: usize = 30;

const BYTES_USED_OFFSET: usize = 40;

fn write_superblock(out: &mut [u8], at: usize, compression_id: u16) {
    let put32 = |out: &mut [u8], field: usize, value: u32| {
        out[at + field..at + field + 4].copy_from_slice(&value.to_le_bytes());
    };
    let put16 = |out: &mut [u8], field: usize, value: u16| {
        out[at + field..at + field + 2].copy_from_slice(&value.to_le_bytes());
    };
    out[at..at + 4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
    put32(out, INODE_COUNT_OFFSET, 517);
    put32(out, BLOCK_SIZE_OFFSET, 131_072);
    put32(out, FRAGMENT_COUNT_OFFSET, 3);
    put16(out, COMPRESSION_ID_OFFSET, compression_id);
    put16(out, VERSION_MAJOR_OFFSET, 4);
    put16(out, VERSION_MINOR_OFFSET, 0);
    out[at + BYTES_USED_OFFSET..at + BYTES_USED_OFFSET + 8]
        .copy_from_slice(&4_293_120u64.to_le_bytes());
}

fn assert_superblock_fields(superblock: &SquashfsSuperblock, compression: SquashfsCompression) {
    assert_eq!(superblock.inode_count, 517, "inode count read from 0x04");
    assert_eq!(superblock.block_size, 131_072, "block size read from 0x0c");
    assert_eq!(
        superblock.fragment_count, 3,
        "fragment count read from 0x10"
    );
    assert_eq!(superblock.compression, compression, "id read from 0x14");
    assert_eq!(superblock.version_major, 4, "major read from 0x1c");
    assert_eq!(superblock.version_minor, 0, "minor read from 0x1e");
    assert_eq!(
        superblock.bytes_used, 4_293_120,
        "bytes used read from 0x28"
    );
    assert!(
        superblock.little_endian,
        "hsqs magic is the little-endian one"
    );
}

fn synth_appimage(offset: usize) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0u8; offset + SUPERBLOCK_MIN_BYTES + 64];
    let out_len: u64 = out.len() as u64;
    out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&2u16.to_le_bytes());
    out[18..20].copy_from_slice(&62u16.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    out[32..40].copy_from_slice(&64u64.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[54..56].copy_from_slice(&56u16.to_le_bytes());
    out[56..58].copy_from_slice(&1u16.to_le_bytes());
    out[64..68].copy_from_slice(&1u32.to_le_bytes());
    out[68..72].copy_from_slice(&5u32.to_le_bytes());
    out[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    out[88..96].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    out[96..104].copy_from_slice(&out_len.to_le_bytes());
    out[104..112].copy_from_slice(&out_len.to_le_bytes());
    out[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    out[8..11].copy_from_slice(&[b'A', b'I', 0x02]);
    write_superblock(&mut out, offset, 6);
    out
}

#[test]
fn appimage_layout_recovered_from_synthetic_binary() {
    let bytes: Vec<u8> = synth_appimage(0x10_000);
    let layout: AppImageLayout = parse_appimage(&bytes).expect("parse appimage");
    assert_eq!(layout.format, AppImageFormat::Type2);
    let AppImagePayloadLayout::Squashfs { offset, superblock } = layout.payload else {
        panic!("type 2 payload was not squashfs");
    };
    assert_eq!(offset, 0x10_000);
    assert_superblock_fields(&superblock, SquashfsCompression::Zstd);
}

#[test]
fn snap_detector_reads_every_superblock_field_at_offset_zero() {
    let mut bytes: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES + 32];
    write_superblock(&mut bytes, 0, 4);
    let parsed: SquashfsSuperblock = detect_snap(&bytes).expect("snap superblock at offset zero");
    assert_superblock_fields(&parsed, SquashfsCompression::Xz);
}
