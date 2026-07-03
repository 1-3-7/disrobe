#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::dmg::{DmgSummary, reconstruct_image};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to_with_quota};

const FIXTURE: &str = "zlib-udif.dmg";
const VARIANT_FIXTURES: [&str; 3] = ["zlib-udif.dmg", "bzip2-udif.dmg", "lzma-udif.dmg"];
const MEMBERS: [&str; 3] = ["hello.txt", "payload.txt", "folder/note.txt"];

fn temp_dir(name: &str) -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-realdmg-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join("dmg")
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth dmg/expected/{rel}"))
}

#[test]
fn real_dmg_koly_blkx_reconstructs_image() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("dmg", FIXTURE) else {
        panic!(
            "missing committed fixture corpus/binfmt/dmg/{FIXTURE} - see corpus/binfmt/MANIFEST.toml"
        );
    };
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Dmg));

    let (image, summary): (Vec<u8>, DmgSummary) =
        reconstruct_image(&bytes).expect("reconstruct dmg image");
    assert!(
        summary.unsupported_chunk_types.is_empty(),
        "fixture must use only in-tree chunk codecs, saw {:?}",
        summary.unsupported_chunk_types
    );
    assert!(summary.chunks > 0, "koly/blkx run table must yield chunks");
    assert!(
        image.windows(2).any(|w: &[u8]| w == b"H+" || w == b"HX"),
        "reconstructed image must contain an HFS+ volume header signature"
    );
}

fn assert_dmg_recovers(fixture: &str, tag: &str) {
    let bytes: Vec<u8> = common::load_fixture("dmg", fixture)
        .unwrap_or_else(|| panic!("missing committed fixture corpus/binfmt/dmg/{fixture}"));
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Dmg));

    let (_image, summary): (Vec<u8>, DmgSummary) =
        reconstruct_image(&bytes).expect("reconstruct dmg image");
    assert!(
        summary.unsupported_chunk_types.is_empty(),
        "{fixture} must use only in-tree chunk codecs, saw {:?}",
        summary.unsupported_chunk_types
    );

    let out: PathBuf = temp_dir(tag);
    let result: ExtractionResult = extract_to_with_quota(
        ContainerKind::Dmg,
        &bytes,
        &out,
        ExtractionQuota::unrestricted(),
    )
    .expect("extract dmg");
    assert_eq!(result.kind, ContainerKind::Dmg);

    for member in MEMBERS {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "hfs+ member {member} not recovered from {fixture}; entries={:?}; violations={:?}",
                result.entries.iter().map(|e| &e.name).collect::<Vec<_>>(),
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from {fixture} must be byte-identical to the source file"
        );
    }
}

#[test]
fn real_dmg_recovers_hfsplus_members_byte_exact() {
    for fixture in VARIANT_FIXTURES {
        let tag: &str = fixture
            .split('-')
            .next()
            .map_or(fixture, |value: &str| value);
        assert_dmg_recovers(fixture, tag);
    }
}
