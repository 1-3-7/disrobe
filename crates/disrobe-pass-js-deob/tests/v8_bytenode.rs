#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, BytenodeCacheHeader, Disassembly, HeaderLayout, NodeVersion,
    ScrapedConstantPool, SnapshotDeserializeStatus, V8_HEADER_SIZE_V11, V8_HEADER_SIZE_V12,
    V8_MAGIC_HIGH_BITS, V8_MAGIC_MARKER_MASK, V8_MAGIC_NODE_18, V8_MAGIC_NODE_20, V8_MAGIC_NODE_22,
    V8_MAGIC_NODE_24, disassemble, parse_bytenode_full, parse_bytenode_header,
    scrape_payload_strings, snapshot_deserialize_status,
};

fn synth_v11_jsc(magic: u32, version: u32, payload_len: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(V8_HEADER_SIZE_V11 + payload_len as usize);
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    out.extend(std::iter::repeat_n(0u8, payload_len as usize));
    out
}

fn synth_v12_jsc(magic: u32, version: u32, payload_len: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(V8_HEADER_SIZE_V12 + payload_len as usize);
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(out.len(), V8_HEADER_SIZE_V12);
    out.extend(std::iter::repeat_n(0u8, payload_len as usize));
    out
}

fn corpus_jsc_path(version_label: &str, basename: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
        .join("corpus/v8")
        .join(format!("node-{version_label}"))
        .join(basename)
}

#[test]
fn detects_node_18_jsc_round_trip_with_real_magic() {
    let bytes: Vec<u8> = synth_v11_jsc(V8_MAGIC_NODE_18, 0x3569_A082, 256);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 18 jsc");
    assert_eq!(header.magic_number, V8_MAGIC_NODE_18);
    assert_eq!(header.version_hash.node, NodeVersion::Node18);
    assert_eq!(header.layout, HeaderLayout::V11);
    assert_eq!(header.payload_length, 256);
}

#[test]
fn detects_node_20_jsc_round_trip_with_real_magic() {
    let bytes: Vec<u8> = synth_v11_jsc(V8_MAGIC_NODE_20, 0x00E4_C20B, 100);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 20 jsc");
    assert_eq!(header.magic_number, V8_MAGIC_NODE_20);
    assert_eq!(header.version_hash.node, NodeVersion::Node20);
    assert_eq!(header.layout, HeaderLayout::V11);
}

#[test]
fn detects_node_22_jsc_round_trip_with_real_magic() {
    let bytes: Vec<u8> = synth_v12_jsc(V8_MAGIC_NODE_22, 0x79DA_FE74, 50);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 22 jsc");
    assert_eq!(header.magic_number, V8_MAGIC_NODE_22);
    assert_eq!(header.version_hash.node, NodeVersion::Node22);
    assert_eq!(header.layout, HeaderLayout::V12);
}

#[test]
fn detects_node_24_jsc_round_trip_with_real_magic() {
    let bytes: Vec<u8> = synth_v12_jsc(V8_MAGIC_NODE_24, 0xDC33_8CFA, 75);
    let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("node 24 jsc");
    assert_eq!(header.magic_number, V8_MAGIC_NODE_24);
    assert_eq!(header.version_hash.node, NodeVersion::Node24);
    assert_eq!(header.layout, HeaderLayout::V12);
}

#[test]
fn magic_high_16_bits_always_0xc0de() {
    for magic in [
        V8_MAGIC_NODE_18,
        V8_MAGIC_NODE_20,
        V8_MAGIC_NODE_22,
        V8_MAGIC_NODE_24,
    ] {
        assert_eq!(magic & !V8_MAGIC_MARKER_MASK, V8_MAGIC_HIGH_BITS);
    }
}

/// HONEST-DOWNGRADE assertion: on real `.jsc` fixtures the disrobe pipeline
/// MUST (a) match the real magic exactly to the bundled-V8 Node version,
/// (b) report the V11 / V12 header layout correctly, (c) emit the typed
/// `SnapshotDeserializeWall` status (NOT a fabricated bytecode-lift), and
/// (d) recover real source strings via the payload scrape.
///
/// "real lift" is gated behind the snapshot-deserialize wall (see
/// `snapshot_deserialize_status`); this test enforces the honest contract.
#[test]
fn real_node_jsc_fixtures_emit_honest_snapshot_wall_and_scrape_source_strings() {
    let cases: [(&str, &str, NodeVersion, u32, HeaderLayout, usize); 4] = [
        (
            "18",
            "hello-18.jsc",
            NodeVersion::Node18,
            V8_MAGIC_NODE_18,
            HeaderLayout::V11,
            V8_HEADER_SIZE_V11,
        ),
        (
            "20",
            "hello-20.jsc",
            NodeVersion::Node20,
            V8_MAGIC_NODE_20,
            HeaderLayout::V11,
            V8_HEADER_SIZE_V11,
        ),
        (
            "22",
            "hello-22.jsc",
            NodeVersion::Node22,
            V8_MAGIC_NODE_22,
            HeaderLayout::V12,
            V8_HEADER_SIZE_V12,
        ),
        (
            "24",
            "hello-24.jsc",
            NodeVersion::Node24,
            V8_MAGIC_NODE_24,
            HeaderLayout::V12,
            V8_HEADER_SIZE_V12,
        ),
    ];
    let mut checked: usize = 0usize;
    for (label, basename, expect_node, expect_magic, expect_layout, expect_hs) in cases {
        let path: PathBuf = corpus_jsc_path(label, basename);
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            continue;
        };
        let body: BytenodeCacheBody =
            parse_bytenode_full(&bytes).unwrap_or_else(|e| panic!("parse {label}: {e}"));
        assert_eq!(
            body.header.magic_number, expect_magic,
            "real .jsc {label}: magic mismatch (got 0x{:08X}, expected 0x{:08X})",
            body.header.magic_number, expect_magic
        );
        assert_eq!(body.header.version_hash.node, expect_node);
        assert_eq!(body.header.layout, expect_layout);
        assert_eq!(body.header.header_size, expect_hs);
        assert_eq!(body.payload_offset, expect_hs);
        assert_eq!(
            body.payload_offset + body.payload_length,
            bytes.len(),
            "real .jsc {label}: header_size + payload_length must equal filesize"
        );
        let status: SnapshotDeserializeStatus = snapshot_deserialize_status(&body.header);
        match status {
            SnapshotDeserializeStatus::SnapshotDeserializeWall {
                node_version,
                v8_version_label,
                reason,
            } => {
                assert_eq!(node_version, expect_node);
                assert!(!v8_version_label.is_empty());
                assert!(reason.contains("snapshot") || reason.contains("Deserializer"));
            }
            unk @ SnapshotDeserializeStatus::UnknownV8Marker { .. } => {
                panic!("real .jsc {label}: expected SnapshotDeserializeWall, got {unk:?}")
            }
        }
        let scraped: ScrapedConstantPool = scrape_payload_strings(&body.payload, 4usize);
        assert!(
            scraped.strings.iter().any(|s: &String| s == "process"),
            "real .jsc {label}: payload scrape missed source identifier `process`; got {:?}",
            scraped.strings
        );
        assert!(
            scraped.strings.iter().any(|s: &String| s == "stdout"),
            "real .jsc {label}: payload scrape missed source identifier `stdout`"
        );
        assert!(
            scraped.strings.iter().any(|s: &String| s == "hello "),
            "real .jsc {label}: payload scrape missed source literal `hello `"
        );
        checked = checked.saturating_add(1);
    }
    assert!(
        checked > 0,
        "no real .jsc fixtures found under corpus/v8/node-{{18,20,22,24}} - \
         this test exists to PROVE real recovery and has nothing to prove without fixtures"
    );
}

/// ANTI-FABRICATION: prove the disassembler does NOT hallucinate a clean
/// Ignition listing out of a real V8 *snapshot* payload. The `.jsc` payload is a
/// `Deserializer::ReadObject` opcode stream, NOT a flat `BytecodeArray`; feeding
/// it to `disassemble` must surface meaningful unknown-opcode / trailing-garbage
/// signal rather than a tidy fabricated lift. This is the honest counter-evidence
/// to the snapshot-deserialize wall.
#[test]
fn real_node_24_snapshot_payload_is_not_a_clean_bytecode_array() {
    let path: PathBuf = corpus_jsc_path("24", "hello-24.jsc");
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
        eprintln!("FIXTURE PENDING: corpus/v8/node-24/hello-24.jsc absent");
        return;
    };
    let body: BytenodeCacheBody = parse_bytenode_full(&bytes).expect("parse node-24");
    let disasm: Disassembly = disassemble(&body.payload, NodeVersion::Node24);
    let unknown_total: usize = disasm.unknown_opcode_counts.values().copied().sum();
    let noise: usize = unknown_total.saturating_add(disasm.trailing_garbage);
    assert!(
        noise > 0usize,
        "real V8 snapshot payload disassembled with ZERO unknown opcodes and ZERO trailing \
         garbage - that would imply a fabricated clean lift of a snapshot stream; \
         instructions={} unknown={} trailing={}",
        disasm.instructions.len(),
        unknown_total,
        disasm.trailing_garbage
    );
}
