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
fn squashfs_full_walk_recovers_members_from_committed_fixtures() {
    use std::io::Read as _;
    use std::path::PathBuf;

    use disrobe_binfmt::container::ContainerKind;
    use disrobe_binfmt::extract_to;

    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut corpus: PathBuf = PathBuf::from(manifest_dir);
    corpus.pop();
    corpus.pop();
    corpus.push("corpus");
    corpus.push("binfmt");
    corpus.push("squashfs-comp");

    for tag in ["gzip", "xz", "zstd", "lz4", "lzo"] {
        let gz: Vec<u8> = std::fs::read(corpus.join(format!("squashfs_{tag}.img.gz")))
            .unwrap_or_else(|_| panic!("missing fixture squashfs_{tag}.img.gz"));
        let mut decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(&gz[..]);
        let mut image: Vec<u8> = Vec::new();
        decoder.read_to_end(&mut image).expect("inflate fixture");

        let out: PathBuf =
            std::env::temp_dir().join(format!("disrobe-fswalk-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let result: disrobe_binfmt::ExtractionResult =
            extract_to(ContainerKind::Squashfs, &image, &out).expect("walk + extract squashfs");
        assert!(
            result.integrity_violations.is_empty(),
            "{tag}: {:?}",
            result.integrity_violations
        );
        let alpha: Vec<u8> = std::fs::read(out.join("dir/alpha.txt"))
            .unwrap_or_else(|_| panic!("{tag}: dir/alpha.txt not recovered"));
        let expected: Vec<u8> =
            std::fs::read(corpus.join("expected/alpha.txt")).expect("read expected/alpha.txt");
        assert_eq!(alpha, expected, "{tag}: alpha.txt must be byte-exact");
        let _ = std::fs::remove_dir_all(&out);
    }
}
