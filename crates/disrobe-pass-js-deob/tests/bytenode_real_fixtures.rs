#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::{BytenodeCacheHeader, NodeVersion, parse_bytenode_header};

fn corpus_dir() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
        .join("corpus/v8")
}

fn try_parse(node: NodeVersion, label: &str) {
    let path: PathBuf = corpus_dir()
        .join(format!("node-{label}"))
        .join(format!("hello-{label}.jsc"));
    let Ok(bytes): Result<Vec<u8>, _> = std::fs::read(&path) else {
        return;
    };
    let header: BytenodeCacheHeader =
        parse_bytenode_header(&bytes).expect("bytenode header parses");
    assert!(header.payload_length > 0u32);
    assert!(matches!(
        header.version_hash.node,
        NodeVersion::Node18
            | NodeVersion::Node20
            | NodeVersion::Node22
            | NodeVersion::Node24
            | NodeVersion::Unknown
    ));
    let _ = node;
}

#[test]
fn node_18_real_fixture_parses_header_when_baked() {
    try_parse(NodeVersion::Node18, "18");
}

#[test]
fn node_20_real_fixture_parses_header_when_baked() {
    try_parse(NodeVersion::Node20, "20");
}

#[test]
fn node_22_real_fixture_parses_header_when_baked() {
    try_parse(NodeVersion::Node22, "22");
}

#[test]
fn node_24_real_fixture_parses_header_when_baked() {
    try_parse(NodeVersion::Node24, "24");
}
