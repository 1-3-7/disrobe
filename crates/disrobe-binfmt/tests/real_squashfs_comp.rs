#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::io::Read as _;
use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::squashfs::{
    SquashfsCompression, SquashfsSuperblock, parse_squashfs_superblock,
};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "squashfs-comp";

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-sqfscomp-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn load_image(tag: &str) -> Vec<u8> {
    let gz: Vec<u8> = common::load_fixture(FORMAT_DIR, &format!("squashfs_{tag}.img.gz"))
        .unwrap_or_else(|| {
            panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/squashfs_{tag}.img.gz")
        });
    let mut decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(&gz[..]);
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out).expect("inflate fixture");
    out
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FORMAT_DIR)
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth {FORMAT_DIR}/expected/{rel}"))
}

fn assert_compressor_recovers_members(tag: &str, want: SquashfsCompression) {
    let image: Vec<u8> = load_image(tag);

    let sb: SquashfsSuperblock =
        parse_squashfs_superblock(&image, 0).expect("parse real squashfs superblock");
    assert_eq!(sb.version_major, 4, "{tag} fixture must be squashfs v4");
    assert!(sb.little_endian, "{tag} fixture must be little-endian");
    assert_eq!(
        sb.compression, want,
        "{tag} fixture superblock must report the {want:?} compressor"
    );

    assert_eq!(
        detect_container(&image),
        Some(ContainerKind::Squashfs),
        "{tag} fixture must be detected as squashfs"
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(tag);

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Squashfs, &image, &out).expect("extract real squashfs");
    assert_eq!(result.kind, ContainerKind::Squashfs);
    assert!(
        result.integrity_violations.is_empty(),
        "{tag} extraction reported violations: {:?}",
        result.integrity_violations
    );

    for (member, expected_name) in [("dir/alpha.txt", "alpha.txt"), ("dir/beta.bin", "beta.bin")] {
        let want_bytes: Vec<u8> = expected_bytes(expected_name);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered from squashfs_{tag}; violations: {:?}",
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want_bytes,
            "{member} from the {tag} squashfs must be byte-identical to the encoder input"
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn squashfs_gzip_recovers_members_byte_exact() {
    assert_compressor_recovers_members("gzip", SquashfsCompression::Gzip);
}

#[test]
fn squashfs_xz_recovers_members_byte_exact() {
    assert_compressor_recovers_members("xz", SquashfsCompression::Xz);
}

#[test]
fn squashfs_zstd_recovers_members_byte_exact() {
    assert_compressor_recovers_members("zstd", SquashfsCompression::Zstd);
}

#[test]
fn squashfs_lz4_recovers_members_byte_exact() {
    assert_compressor_recovers_members("lz4", SquashfsCompression::Lz4);
}

#[test]
fn squashfs_lzo_recovers_members_byte_exact() {
    assert_compressor_recovers_members("lzo", SquashfsCompression::Lzo);
}
