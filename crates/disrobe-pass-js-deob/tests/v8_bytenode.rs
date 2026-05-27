#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::bytenode::{
    BYTENODE_PREFIX_BYTES, BytenodeCacheHeader, NodeVersion, V8_CACHED_DATA_MAGIC,
    parse_bytenode_header,
};

fn synth_jsc(version: u32, payload_len: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(BYTENODE_PREFIX_BYTES + payload_len as usize);
    out.extend_from_slice(&V8_CACHED_DATA_MAGIC.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
    out.extend(std::iter::repeat_n(0u8, payload_len as usize));
    out
}

#[test]
fn detects_node_18_jsc_round_trip() {
    let bytes: Vec<u8> = synth_jsc(0xA5A5_18A5, 256);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 18 jsc");
    assert_eq!(header.version_hash.node, NodeVersion::Node18);
    assert_eq!(header.payload_length, 256);
}

#[test]
fn detects_node_20_jsc_round_trip() {
    let bytes: Vec<u8> = synth_jsc(0xA5A5_20A5, 100);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 20");
    assert_eq!(header.version_hash.node, NodeVersion::Node20);
}

#[test]
fn detects_node_22_jsc_round_trip() {
    let bytes: Vec<u8> = synth_jsc(0xA5A5_22A5, 50);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 22");
    assert_eq!(header.version_hash.node, NodeVersion::Node22);
}

#[test]
fn detects_node_24_jsc_round_trip() {
    let bytes: Vec<u8> = synth_jsc(0xA5A5_24A5, 75);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 24");
    assert_eq!(header.version_hash.node, NodeVersion::Node24);
}

#[test]
#[ignore = "BLOCKER: bytenode lift requires per-Node-version V8 opcode tables; real .jsc fixtures need bytenode-compiled scripts (license-clean fixture corpus not yet built — defer to v0.3)"]
fn bytenode_lift_to_js_surface_real_node_jsc() {
    panic!("ignored: needs real bytenode .jsc fixtures");
}
