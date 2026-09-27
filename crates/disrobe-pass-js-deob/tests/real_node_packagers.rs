#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::v8::{
    BytenodeCacheHeader, NodeVersion, SEA_MAGIC, SeaBlob, V8_MAGIC_HIGH_BITS, V8_MAGIC_MARKER_MASK,
    parse_bytenode_header, parse_sea_blob,
};

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load_bytes(rel: &str) -> Vec<u8> {
    let p: PathBuf = corpus_path(rel);
    fs::read(&p).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "tracked corpus fixture {} is required: {error}",
            p.display()
        )
    })
}

#[test]
fn real_sea_prep_blob_parses_via_node_sea_parser_with_real_magic() {
    let bytes: Vec<u8> = load_bytes("sea/sea-prep.blob");
    assert!(
        bytes.len() >= 10,
        "real sea-prep.blob must have at least 10 header bytes; got {}",
        bytes.len()
    );
    assert_eq!(
        &bytes[..4],
        &SEA_MAGIC.to_le_bytes(),
        "real sea-prep.blob must start with SEA_MAGIC 0x{SEA_MAGIC:08X}"
    );
    let blob: SeaBlob = parse_sea_blob(&bytes).expect("real SEA parses");
    assert_eq!(blob.magic, SEA_MAGIC);
    assert!(!blob.code_path.is_empty());
    assert!(
        std::path::Path::new(&blob.code_path)
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("js"))
    );
    assert!(blob.main_code_len > 0u64);
}

#[test]
fn real_pkg_header_has_mz_pe_signature() {
    let bytes: Vec<u8> = load_bytes("pkg/hello-pkg-header.bin");
    assert!(bytes.len() >= 2);
    assert_eq!(
        &bytes[..2],
        b"MZ",
        "pkg-built Windows exe must start with MZ"
    );
}

#[test]
fn real_pkg_tail_has_payload_markers() {
    let bytes: Vec<u8> = load_bytes("pkg/hello-pkg-tail.bin");
    assert!(
        bytes.len() > 1024,
        "pkg tail must contain real payload bytes"
    );
}

#[test]
fn real_bytenode_node18_jsc_parses_via_header_parser() {
    let p: PathBuf = {
        let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .join("..")
            .join("..")
            .join("corpus")
            .join("v8")
            .join("node-18")
            .join("hello-18.jsc")
    };
    let bytes: Vec<u8> = fs::read(&p).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "tracked corpus fixture {} is required: {error}",
            p.display()
        )
    });
    assert!(bytes.len() > 16, "bytenode .jsc must have V8 header bytes");
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("real jsc parses");
    assert_eq!(
        header.magic_number & !V8_MAGIC_MARKER_MASK,
        V8_MAGIC_HIGH_BITS
    );
    assert_eq!(header.version_hash.node, NodeVersion::Node18);
}
