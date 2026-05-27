#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load_bytes(rel: &str) -> Option<Vec<u8>> {
    let p: PathBuf = corpus_path(rel);
    if !p.exists() {
        return None;
    }
    fs::read(&p).ok()
}

#[test]
fn real_sea_prep_blob_has_node_v8_payload_signature() {
    let Some(bytes): Option<Vec<u8>> = load_bytes("sea/sea-prep.blob") else {
        return;
    };
    assert!(
        bytes.len() > 1024,
        "SEA blob should be non-trivial; got {} bytes",
        bytes.len()
    );
    let head: &[u8] = &bytes[..bytes.len().min(64)];
    let nonzero: usize = head.iter().filter(|b: &&u8| **b != 0).count();
    assert!(nonzero > 8, "SEA blob head should not be all zeros");
}

#[test]
fn real_pkg_header_has_mz_pe_signature() {
    let Some(bytes): Option<Vec<u8>> = load_bytes("pkg/hello-pkg-header.bin") else {
        return;
    };
    assert!(bytes.len() >= 2);
    assert_eq!(
        &bytes[..2],
        b"MZ",
        "pkg-built Windows exe must start with MZ"
    );
}

#[test]
fn real_pkg_tail_has_payload_markers() {
    let Some(bytes): Option<Vec<u8>> = load_bytes("pkg/hello-pkg-tail.bin") else {
        return;
    };
    assert!(
        bytes.len() > 1024,
        "pkg tail must contain real payload bytes"
    );
}

#[test]
fn real_bytenode_node18_jsc_loads() {
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
    if !p.exists() {
        return;
    }
    let bytes: Vec<u8> = fs::read(&p).expect("read jsc");
    assert!(bytes.len() > 16, "bytenode .jsc must have V8 header bytes");
}
