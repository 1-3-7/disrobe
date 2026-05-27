#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;

use disrobe_pass_as3::swf::{Swf, SwfCompression, TagCode};
use disrobe_pass_as3::{AbcFile, DoAbc, abc, decompile, swf};

fn corpus_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(name);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

#[test]
fn detects_uncompressed_fws_signature() {
    let bytes: Vec<u8> = read_fixture("A-Blast_Liberation.swf");
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::None);
}

#[test]
fn detects_zlib_cws_signature() {
    let bytes: Vec<u8> = read_fixture("4_Ball_Pong.swf");
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::Zlib);
}

#[test]
fn detects_lzma_zws_signature() {
    let bytes: Vec<u8> = read_fixture("10_More_Bullets.swf");
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::Lzma);
}

#[test]
fn parses_real_uncompressed_swf_header_and_tags() {
    let bytes: Vec<u8> = read_fixture("A-Blast_Liberation.swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse FWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::None);
    assert!(parsed.header.version >= 1);
    assert!(parsed.header.frame_count >= 1);
    assert!(
        parsed.tags.len() >= 5,
        "expected non-trivial tag stream, got {}",
        parsed.tags.len()
    );
    assert!(
        parsed
            .tags
            .iter()
            .any(|t: &swf::SwfTag| t.code == TagCode::END)
    );
}

#[test]
fn parses_real_zlib_swf_header_and_tags() {
    let bytes: Vec<u8> = read_fixture("4_Ball_Pong.swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse CWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::Zlib);
    assert!(parsed.header.version >= 6);
    assert!(parsed.tags.len() >= 5);
}

#[test]
fn parses_real_lzma_swf_extracts_do_abc_tags() {
    let bytes: Vec<u8> = read_fixture("10_More_Bullets.swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse ZWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::Lzma);
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    assert!(
        !abc_blobs.is_empty(),
        "AS3-era LZMA SWF should contain at least one DoABC tag"
    );
    for blob in &abc_blobs {
        assert!(!blob.abc_bytes.is_empty(), "DoABC payload empty");
        let _ = abc::parse(&blob.abc_bytes);
    }
}

#[test]
fn parses_real_zlib_3d_motorbike_walks_tag_counts() {
    let bytes: Vec<u8> = read_fixture("3D_Motorbike_Racer.swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse swf");
    let counts: std::collections::BTreeMap<TagCode, usize> = parsed.tag_counts();
    assert!(!counts.is_empty());
    let total: usize = counts.values().sum();
    assert!(
        total >= 20,
        "expected many tags in 3D_Motorbike_Racer.swf, got {total}"
    );
}

#[test]
fn parses_real_atv_megafile_swf_walks_tags() {
    let bytes: Vec<u8> = read_fixture("ATV_Cross_Canada.swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse megafile swf");
    assert!(parsed.header.version >= 10, "ATV is AS3-era v11");
    let counts: std::collections::BTreeMap<TagCode, usize> = parsed.tag_counts();
    let total: usize = counts.values().sum();
    assert!(
        total >= 50,
        "expected megafile SWF to have many tags, got {total}"
    );
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    let mut total_classes: usize = 0;
    let mut total_decompiled: usize = 0;
    for blob in &abc_blobs {
        let abc: AbcFile = match abc::parse(&blob.abc_bytes) {
            Ok(a) => a,
            Err(_) => continue,
        };
        total_classes += abc.instances.len();
        for instance in &abc.instances {
            if let Ok(skel) = decompile::render_class_skeleton(&abc, instance) {
                assert!(skel.contains("class ") || skel.contains("interface "));
                total_decompiled += 1;
            }
        }
    }
    let _ = (total_classes, total_decompiled);
}

#[test]
fn parses_4_wheel_madness_zlib_swf_tags_and_abc() {
    let bytes: Vec<u8> = read_fixture("4_Wheel_Madness.swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse swf");
    assert_eq!(parsed.header.compression, SwfCompression::Zlib);
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    for blob in &abc_blobs {
        let abc: AbcFile = abc::parse(&blob.abc_bytes)
            .unwrap_or_else(|e: disrobe_pass_as3::Error| panic!("parse abc '{}': {e}", blob.name));
        assert_eq!(abc.minor, abc::ABC_MINOR);
        assert_eq!(abc.major, abc::ABC_MAJOR);
    }
}

#[test]
fn rejects_truncated_real_swf() {
    let mut bytes: Vec<u8> = read_fixture("A-Blast_Liberation.swf");
    bytes.truncate(8);
    let _ = swf::parse(&bytes).expect_err("must fail on truncated body");
}

#[test]
fn rejects_corrupted_magic_signature() {
    let mut bytes: Vec<u8> = read_fixture("3D_Frogger.swf");
    bytes[0] = b'X';
    let err: disrobe_pass_as3::Error = swf::parse(&bytes).expect_err("must reject bad magic");
    let msg: String = err.to_string();
    assert!(msg.contains("DR-AS3") || msg.contains("signature") || msg.contains("Bad"));
}
