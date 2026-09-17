use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const V8_MAGIC_HIGH_BITS: u32 = 0xC0DE_0000;

pub const V8_MAGIC_MARKER_MASK: u32 = 0x0000_FFFF;

pub const V8_MAGIC_NODE_18: u32 = 0xC0DE_0563;

pub const V8_MAGIC_NODE_20: u32 = 0xC0DE_05CC;

pub const V8_MAGIC_NODE_22: u32 = 0xC0DE_0628;

pub const V8_MAGIC_NODE_24: u32 = 0xC0DE_0688;

pub const V8_HEADER_SIZE_V11: usize = 24usize;

pub const V8_HEADER_SIZE_V12: usize = 32usize;

pub const V8_MAX_PAYLOAD_BYTES: usize = 256usize * 1024usize * 1024usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeVersion {
    Node18,
    Node20,
    Node22,
    Node24,
    Unknown,
}

impl NodeVersion {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Node18 => "node-18",
            Self::Node20 => "node-20",
            Self::Node22 => "node-22",
            Self::Node24 => "node-24",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn from_v8_magic(magic: u32) -> Self {
        if magic & !V8_MAGIC_MARKER_MASK != V8_MAGIC_HIGH_BITS {
            return Self::Unknown;
        }
        match magic {
            V8_MAGIC_NODE_18 => Self::Node18,
            V8_MAGIC_NODE_20 => Self::Node20,
            V8_MAGIC_NODE_22 => Self::Node22,
            V8_MAGIC_NODE_24 => Self::Node24,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn header_layout(self) -> HeaderLayout {
        match self {
            Self::Node18 | Self::Node20 => HeaderLayout::V11,
            Self::Node22 | Self::Node24 | Self::Unknown => HeaderLayout::V12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderLayout {
    V11,

    V12,
}

impl HeaderLayout {
    #[must_use]
    pub const fn header_size(self) -> usize {
        match self {
            Self::V11 => V8_HEADER_SIZE_V11,
            Self::V12 => V8_HEADER_SIZE_V12,
        }
    }

    #[must_use]
    pub const fn payload_length_offset(self) -> usize {
        match self {
            Self::V11 => 16usize,
            Self::V12 => 20usize,
        }
    }

    #[must_use]
    pub const fn checksum_offset(self) -> usize {
        match self {
            Self::V11 => 20usize,
            Self::V12 => 24usize,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteVersion {
    pub raw: u32,
    pub node: NodeVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytenodeCacheHeader {
    pub magic_number: u32,
    pub version_hash: ByteVersion,
    pub source_hash: u32,
    pub flag_hash: u32,

    pub read_only_snapshot_checksum: Option<u32>,
    pub payload_length: u32,
    pub checksum: u32,
    pub layout: HeaderLayout,
    pub header_size: usize,
    pub raw_header_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytenodeCacheBody {
    pub header: BytenodeCacheHeader,
    pub payload_offset: usize,
    pub payload_length: usize,

    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum SnapshotDeserializeStatus {
    KnownV8Version {
        node_version: NodeVersion,
        v8_version_label: &'static str,
        graph_parse_supported: bool,
        note: &'static str,
    },

    UnknownV8Marker {
        magic_low: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrapedConstantPool {
    pub strings: Vec<String>,
    pub min_run: usize,
}

#[must_use]
pub fn looks_like_bytenode(bytes: &[u8]) -> bool {
    parse_bytenode_header(bytes).is_ok()
}

pub fn parse_bytenode_header(bytes: &[u8]) -> Result<BytenodeCacheHeader> {
    if bytes.len() < V8_HEADER_SIZE_V11 {
        return Err(Error::OxcParse(format!(
            "bytenode header too short: need at least {V8_HEADER_SIZE_V11} bytes, got {}",
            bytes.len()
        )));
    }
    let magic_number: u32 = read_u32_le(bytes, 0)?;
    if magic_number & !V8_MAGIC_MARKER_MASK != V8_MAGIC_HIGH_BITS {
        return Err(Error::OxcParse(format!(
            "bytenode magic mismatch: got 0x{magic_number:08X}, expected high16 == 0xC0DE \
             (V8 SerializedCodeData::kMagicNumber)"
        )));
    }
    let node: NodeVersion = NodeVersion::from_v8_magic(magic_number);
    let layout: HeaderLayout = pick_header_layout(bytes, node);
    if bytes.len() < layout.header_size() {
        return Err(Error::OxcParse(format!(
            "bytenode header truncated: layout {:?} needs {} bytes, got {}",
            layout,
            layout.header_size(),
            bytes.len()
        )));
    }
    let version_raw: u32 = read_u32_le(bytes, 4)?;
    let source_hash: u32 = read_u32_le(bytes, 8)?;
    let flag_hash: u32 = read_u32_le(bytes, 12)?;
    let read_only_snapshot_checksum: Option<u32> = match layout {
        HeaderLayout::V11 => None,
        HeaderLayout::V12 => Some(read_u32_le(bytes, 16)?),
    };
    let payload_length: u32 = read_u32_le(bytes, layout.payload_length_offset())?;
    let checksum: u32 = read_u32_le(bytes, layout.checksum_offset())?;
    let payload_len_usize: usize = payload_length as usize;
    if payload_len_usize > V8_MAX_PAYLOAD_BYTES {
        return Err(Error::OxcParse(format!(
            "bytenode payload_length {payload_len_usize} exceeds V8_MAX_PAYLOAD_BYTES \
             ({V8_MAX_PAYLOAD_BYTES}); refusing to allocate 1.6GB-class garbage"
        )));
    }
    let max_payload_for_input: usize = bytes.len().saturating_sub(layout.header_size());
    if payload_len_usize > max_payload_for_input {
        return Err(Error::OxcParse(format!(
            "bytenode payload_length {payload_len_usize} exceeds available input \
             ({max_payload_for_input} bytes after {}-byte header)",
            layout.header_size()
        )));
    }
    let raw_header_bytes: Vec<u8> = bytes[..layout.header_size()].to_vec();
    Ok(BytenodeCacheHeader {
        magic_number,
        version_hash: ByteVersion {
            raw: version_raw,
            node,
        },
        source_hash,
        flag_hash,
        read_only_snapshot_checksum,
        payload_length,
        checksum,
        layout,
        header_size: layout.header_size(),
        raw_header_bytes,
    })
}

pub fn parse_bytenode_full(bytes: &[u8]) -> Result<BytenodeCacheBody> {
    let header: BytenodeCacheHeader = parse_bytenode_header(bytes)?;
    let payload_offset: usize = header.header_size;
    let payload_length: usize = header.payload_length as usize;
    let payload_end: usize = payload_offset
        .checked_add(payload_length)
        .ok_or_else(|| Error::OxcParse("bytenode payload end overflows usize".to_owned()))?;
    if payload_end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "bytenode payload extends past input: end={payload_end}, len={}",
            bytes.len()
        )));
    }
    let payload: Vec<u8> = bytes[payload_offset..payload_end].to_vec();
    Ok(BytenodeCacheBody {
        header,
        payload_offset,
        payload_length,
        payload,
    })
}

#[must_use]
pub fn snapshot_deserialize_status(header: &BytenodeCacheHeader) -> SnapshotDeserializeStatus {
    match header.version_hash.node {
        NodeVersion::Node18 => SnapshotDeserializeStatus::KnownV8Version {
            node_version: NodeVersion::Node18,
            v8_version_label: "v10.2",
            graph_parse_supported: true,
            note: GRAPH_SUPPORTED_NOTE,
        },
        NodeVersion::Node20 => SnapshotDeserializeStatus::KnownV8Version {
            node_version: NodeVersion::Node20,
            v8_version_label: "v11.3",
            graph_parse_supported: true,
            note: GRAPH_SUPPORTED_NOTE,
        },
        NodeVersion::Node22 => SnapshotDeserializeStatus::KnownV8Version {
            node_version: NodeVersion::Node22,
            v8_version_label: "v12.4",
            graph_parse_supported: true,
            note: GRAPH_SUPPORTED_NOTE,
        },
        NodeVersion::Node24 => SnapshotDeserializeStatus::KnownV8Version {
            node_version: NodeVersion::Node24,
            v8_version_label: "v13.6",
            graph_parse_supported: true,
            note: GRAPH_SUPPORTED_NOTE,
        },
        NodeVersion::Unknown => SnapshotDeserializeStatus::UnknownV8Marker {
            magic_low: u16::try_from(header.magic_number & V8_MAGIC_MARKER_MASK).unwrap_or(0u16),
        },
    }
}

const GRAPH_SUPPORTED_NOTE: &str = "the payload is a CodeSerializer object graph (Deserializer::ReadObject opcodes over \
     NewObject / backref / RootArray slots); code_serializer::parse_code_serializer_graph walks it \
     and recovers each BytecodeArray's inline bytecode byte-exact for this v8 release, plus links \
     each function's constant-pool FixedArray. User-defined identifiers, property names and string \
     literals are serialized inline in that pool and are recovered as readable names; only common \
     builtin and single-character root strings (length, push, console, \"!\", ...) are RootArray / \
     ReadOnlyHeapRef indices, resolved through a pinned per-release root-name table, and an \
     unpinned-build root stays an index honestly.";

#[must_use]
pub fn scrape_payload_strings(payload: &[u8], min_run: usize) -> ScrapedConstantPool {
    let min: usize = min_run.max(1usize);
    let mut strings: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut run_start: Option<usize> = None;
    for (i, &b) in payload.iter().enumerate() {
        let printable: bool = matches!(b, 0x20u8..=0x7Eu8);
        match (printable, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(start)) => {
                push_run(&payload[start..i], min, &mut strings, &mut seen);
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = run_start {
        push_run(&payload[start..], min, &mut strings, &mut seen);
    }
    ScrapedConstantPool {
        strings,
        min_run: min,
    }
}

fn push_run(run: &[u8], min: usize, out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    if run.len() < min {
        return;
    }
    let Ok(s): std::result::Result<&str, _> = std::str::from_utf8(run) else {
        return;
    };
    let owned: String = s.to_owned();
    if seen.insert(owned.clone()) {
        out.push(owned);
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end: usize = offset
        .checked_add(4usize)
        .ok_or_else(|| Error::OxcParse("u32 read offset overflows usize".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "u32 read out of bounds: offset={offset}, end={end}, len={}",
            bytes.len()
        )));
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1usize],
        bytes[offset + 2usize],
        bytes[offset + 3usize],
    ]))
}

fn pick_header_layout(bytes: &[u8], node: NodeVersion) -> HeaderLayout {
    let direct: HeaderLayout = node.header_layout();
    if node != NodeVersion::Unknown && self_describes(bytes, direct) {
        return direct;
    }
    if self_describes(bytes, HeaderLayout::V12) {
        return HeaderLayout::V12;
    }
    if self_describes(bytes, HeaderLayout::V11) {
        return HeaderLayout::V11;
    }
    direct
}

fn self_describes(bytes: &[u8], layout: HeaderLayout) -> bool {
    let hs: usize = layout.header_size();
    let plo: usize = layout.payload_length_offset();
    if bytes.len() < hs || plo + 4usize > bytes.len() {
        return false;
    }
    let Ok(pl): Result<u32> = read_u32_le(bytes, plo) else {
        return false;
    };
    let pl_usize: usize = pl as usize;
    if pl_usize > V8_MAX_PAYLOAD_BYTES {
        return false;
    }
    hs.saturating_add(pl_usize) == bytes.len()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_v11_jsc(magic: u32, version: u32, payload_len: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(V8_HEADER_SIZE_V11 + payload_len as usize);
        out.extend_from_slice(&magic.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        out.extend(std::iter::repeat_n(0u8, payload_len as usize));
        out
    }

    fn synth_v12_jsc(magic: u32, version: u32, payload_len: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(V8_HEADER_SIZE_V12 + payload_len as usize);
        out.extend_from_slice(&magic.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0xCAFE_BABE_u32.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(out.len(), V8_HEADER_SIZE_V12);
        out.extend(std::iter::repeat_n(0u8, payload_len as usize));
        out
    }

    #[test]
    fn looks_like_bytenode_accepts_valid_and_rejects_garbage() {
        let valid: Vec<u8> = synth_v11_jsc(V8_MAGIC_NODE_18, 0x3569_A082, 32);
        assert!(looks_like_bytenode(&valid));
        assert!(!looks_like_bytenode(&[0u8; 64]));
        assert!(!looks_like_bytenode(b"const x = 1;"));
    }

    #[test]
    fn parses_node_18_real_magic_v11_layout() {
        let bytes: Vec<u8> = synth_v11_jsc(V8_MAGIC_NODE_18, 0x3569_A082, 96);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("parse jsc");
        assert_eq!(header.magic_number, V8_MAGIC_NODE_18);
        assert_eq!(header.version_hash.node, NodeVersion::Node18);
        assert_eq!(header.layout, HeaderLayout::V11);
        assert_eq!(header.header_size, V8_HEADER_SIZE_V11);
        assert_eq!(header.payload_length, 96);
        assert_eq!(header.checksum, 0xDEAD_BEEF);
        assert!(header.read_only_snapshot_checksum.is_none());
    }

    #[test]
    fn parses_node_24_real_magic_v12_layout() {
        let bytes: Vec<u8> = synth_v12_jsc(V8_MAGIC_NODE_24, 0xDC33_8CFA, 128);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("parse jsc");
        assert_eq!(header.magic_number, V8_MAGIC_NODE_24);
        assert_eq!(header.version_hash.node, NodeVersion::Node24);
        assert_eq!(header.layout, HeaderLayout::V12);
        assert_eq!(header.header_size, V8_HEADER_SIZE_V12);
        assert_eq!(header.payload_length, 128);
        assert_eq!(header.read_only_snapshot_checksum, Some(0xCAFE_BABE));
    }

    #[test]
    fn rejects_bogus_magic_no_garbage_disasm() {
        let bytes: Vec<u8> = synth_v11_jsc(0xDEAD_BEEF, 0x1234_5678, 16);
        let err: Error = parse_bytenode_header(&bytes).unwrap_err();
        match err {
            Error::OxcParse(msg) => assert!(msg.contains("magic mismatch"), "msg={msg}"),
            other => panic!("expected OxcParse, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_payload_length_dos_guard() {
        let mut bytes: Vec<u8> = synth_v11_jsc(V8_MAGIC_NODE_18, 0x1111_1111, 4);
        let huge: u32 = 0x4000_0000;
        bytes[16..20].copy_from_slice(&huge.to_le_bytes());
        let err: Error = parse_bytenode_header(&bytes).unwrap_err();
        match err {
            Error::OxcParse(msg) => assert!(msg.contains("exceeds"), "msg={msg}"),
            other => panic!("expected OxcParse, got {other:?}"),
        }
    }

    #[test]
    fn rejects_payload_length_past_input() {
        let mut bytes: Vec<u8> = synth_v11_jsc(V8_MAGIC_NODE_18, 0x1111_1111, 8);
        let too_big: u32 = 1024u32;
        bytes[16..20].copy_from_slice(&too_big.to_le_bytes());
        let err: Error = parse_bytenode_header(&bytes).unwrap_err();
        match err {
            Error::OxcParse(msg) => assert!(msg.contains("exceeds available input"), "msg={msg}"),
            other => panic!("expected OxcParse, got {other:?}"),
        }
    }

    #[test]
    fn rejects_short_header() {
        let bytes: Vec<u8> = vec![0u8; 10];
        let err: Error = parse_bytenode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::OxcParse(_)));
    }

    #[test]
    fn unknown_v8_marker_high_bits_match_but_low_unknown() {
        let bytes: Vec<u8> = synth_v11_jsc(0xC0DE_9999, 0x1234_5678, 16);
        let header: BytenodeCacheHeader =
            parse_bytenode_header(&bytes).expect("unknown low marker still parses");
        assert_eq!(header.version_hash.node, NodeVersion::Unknown);
        match snapshot_deserialize_status(&header) {
            SnapshotDeserializeStatus::UnknownV8Marker { magic_low } => {
                assert_eq!(magic_low, 0x9999u16);
            }
            known @ SnapshotDeserializeStatus::KnownV8Version { .. } => {
                panic!("expected UnknownV8Marker, got {known:?}");
            }
        }
    }

    #[test]
    fn node24_status_reports_graph_parse_supported() {
        let bytes: Vec<u8> = synth_v12_jsc(V8_MAGIC_NODE_24, 0xDC33_8CFA, 32);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("parse");
        match snapshot_deserialize_status(&header) {
            SnapshotDeserializeStatus::KnownV8Version {
                node_version,
                v8_version_label,
                graph_parse_supported,
                note,
            } => {
                assert_eq!(node_version, NodeVersion::Node24);
                assert_eq!(v8_version_label, "v13.6");
                assert!(
                    graph_parse_supported,
                    "node-24 / v8-13.6 has a working object-graph parser"
                );
                assert!(note.contains("byte-exact"));
            }
            unk @ SnapshotDeserializeStatus::UnknownV8Marker { .. } => {
                panic!("expected KnownV8Version, got {unk:?}");
            }
        }
    }

    #[test]
    fn node_18_20_22_status_reports_graph_parse_supported() {
        for (magic, expected) in [
            (V8_MAGIC_NODE_18, NodeVersion::Node18),
            (V8_MAGIC_NODE_20, NodeVersion::Node20),
            (V8_MAGIC_NODE_22, NodeVersion::Node22),
        ] {
            let bytes: Vec<u8> = synth_v12_jsc(magic, 0x79DA_FE74, 32);
            let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("parse");
            match snapshot_deserialize_status(&header) {
                SnapshotDeserializeStatus::KnownV8Version {
                    node_version,
                    graph_parse_supported,
                    note,
                    ..
                } => {
                    assert_eq!(node_version, expected);
                    assert!(
                        graph_parse_supported,
                        "{expected:?} has its own object-graph opcode map"
                    );
                    assert!(note.contains("byte-exact"));
                }
                unk @ SnapshotDeserializeStatus::UnknownV8Marker { .. } => {
                    panic!("expected KnownV8Version, got {unk:?}");
                }
            }
        }
    }

    #[test]
    fn node_version_label_round_trip() {
        assert_eq!(NodeVersion::Node18.label(), "node-18");
        assert_eq!(NodeVersion::Node24.label(), "node-24");
        assert_eq!(NodeVersion::Unknown.label(), "unknown");
    }

    #[test]
    fn header_layout_constants_match_v8_kheadersize() {
        assert_eq!(HeaderLayout::V11.header_size(), 24usize);
        assert_eq!(HeaderLayout::V11.payload_length_offset(), 16usize);
        assert_eq!(HeaderLayout::V12.header_size(), 32usize);
        assert_eq!(HeaderLayout::V12.payload_length_offset(), 20usize);
    }

    #[test]
    fn scrape_payload_strings_recovers_ascii_runs() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&[0u8, 1u8, 2u8]);
            v.extend_from_slice(b"process");
            v.extend_from_slice(&[0u8, 0u8]);
            v.extend_from_slice(b"hello world");
            v.extend_from_slice(&[0xFFu8]);
            v.extend_from_slice(b"ab");
            v
        };
        let scraped: ScrapedConstantPool = scrape_payload_strings(&payload, 4usize);
        assert!(scraped.strings.contains(&"process".to_owned()));
        assert!(scraped.strings.contains(&"hello world".to_owned()));
        assert!(!scraped.strings.iter().any(|s: &String| s == "ab"));
    }

    #[test]
    fn parse_full_body_returns_correct_payload_slice() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xFFusize).unwrap();
        }
        let mut bytes: Vec<u8> = synth_v12_jsc(V8_MAGIC_NODE_22, 0x79DA_FE74, 64);
        bytes[V8_HEADER_SIZE_V12..].copy_from_slice(&payload);
        let body: BytenodeCacheBody = parse_bytenode_full(&bytes).expect("parse_full");
        assert_eq!(body.payload_offset, V8_HEADER_SIZE_V12);
        assert_eq!(body.payload_length, 64);
        assert_eq!(body.payload, payload);
        assert_eq!(body.header.version_hash.node, NodeVersion::Node22);
    }
}
