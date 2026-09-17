#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::io::Read as _;
use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::squashfs::{
    SquashfsCompression, SquashfsSuperblock, parse_squashfs_superblock,
};
use disrobe_binfmt::extract::extract_to_with_quota;
use disrobe_binfmt::quota::ExtractionQuota;
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

const REAL_TAGS: [&str; 5] = ["gzip", "xz", "zstd", "lzo", "lz4"];
const EXTERNAL_TOOL_CLAIMS: [&str; 3] = ["external", "decoder", "unsquashfs"];

const fn tight_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_entries: 8,
        max_total_uncompressed: 64 * 1024,
        max_per_entry_uncompressed: 16,
        max_per_entry_ratio: 1_000,
        max_aggregate_ratio: 1_000,
    }
}

#[test]
fn a_real_image_whose_regular_entries_all_hit_the_quota_keeps_its_quota_diagnosis() {
    for tag in REAL_TAGS {
        let image: Vec<u8> = load_image(tag);
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir(&format!("{tag}-quota"));
        let result: ExtractionResult = extract_to_with_quota(
            ContainerKind::Squashfs,
            &image,
            scratch.path(),
            tight_quota(),
        )
        .unwrap_or_else(|error: disrobe_binfmt::Error| {
            panic!(
                "{tag}: a quota refusal must stay a per-entry violation rather than becoming a \
                 whole-image failure, got {error}"
            )
        });
        assert!(
            result.entries.is_empty(),
            "{tag}: no entry may be written once every regular member exceeds the quota"
        );
        assert_eq!(
            result.integrity_violations.len(),
            2,
            "{tag}: both regular members must record a quota violation: {:?}",
            result.integrity_violations
        );
        for line in &result.integrity_violations {
            assert!(
                line.starts_with("squashfs-quota "),
                "{tag}: a quota refusal must keep its precise tag: {line}"
            );
            let folded: String = line.to_ascii_lowercase();
            for claim in EXTERNAL_TOOL_CLAIMS {
                assert!(
                    !folded.contains(claim),
                    "{tag}: a quota refusal must not blame a missing decoder: {line}"
                );
            }
        }
    }
}

#[test]
fn every_real_compressor_extracts_in_process_without_a_violation() {
    for tag in REAL_TAGS {
        let image: Vec<u8> = load_image(tag);
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir(&format!("{tag}-clean"));
        let result: ExtractionResult = extract_to(ContainerKind::Squashfs, &image, scratch.path())
            .unwrap_or_else(|error: disrobe_binfmt::Error| {
                panic!("{tag}: real image must extract in process: {error}")
            });
        assert_eq!(
            result.entries.len(),
            2,
            "{tag}: both regular members must be written"
        );
        assert!(
            result.integrity_violations.is_empty(),
            "{tag}: a clean real image must record no violation: {:?}",
            result.integrity_violations
        );
    }
}
