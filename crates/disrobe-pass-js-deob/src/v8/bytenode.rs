use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// High 16 bits of every V8 `SerializedCodeData::kMagicNumber`.
///
/// The low 16 bits are a per-V8-version marker (see [`NodeVersion::from_v8_magic`]).
/// Source: V8 `src/snapshot/code-serializer.cc`, `SerializedData::kMagicNumber`
/// initializer (`kMagicNumberBase ^ ...`); empirically `magic >> 16 == 0xC0DE`
/// across V8 10.2 / 11.3 / 12.4 / 13.6 (Node 18 / 20 / 22 / 24).
pub const V8_MAGIC_HIGH_BITS: u32 = 0xC0DE_0000;

/// Mask isolating the V8-version marker in the low 16 bits of the magic.
pub const V8_MAGIC_MARKER_MASK: u32 = 0x0000_FFFF;

/// V8 `SerializedCodeData` magic for Node 18 (V8 10.2).
pub const V8_MAGIC_NODE_18: u32 = 0xC0DE_0563;
/// V8 `SerializedCodeData` magic for Node 20 (V8 11.3).
pub const V8_MAGIC_NODE_20: u32 = 0xC0DE_05CC;
/// V8 `SerializedCodeData` magic for Node 22 (V8 12.4).
pub const V8_MAGIC_NODE_22: u32 = 0xC0DE_0628;
/// V8 `SerializedCodeData` magic for Node 24 (V8 13.6).
pub const V8_MAGIC_NODE_24: u32 = 0xC0DE_0688;

/// Legacy alias kept for downstream code that imported the old (fake) symbol.
/// Equal to [`V8_MAGIC_NODE_24`] - the most likely match for current Node releases.
#[deprecated(
    since = "0.3.0",
    note = "fake constant; use V8_MAGIC_NODE_{18,20,22,24} or detect via parse_bytenode_header"
)]
pub const V8_CACHED_DATA_MAGIC: u32 = V8_MAGIC_NODE_24;

/// V8 `SerializedCodeData` header layout for Node 18 / 20 (V8 ≤ 11.x).
///
/// Field order (each `u32`, little-endian):
/// 1. `magic_number`
/// 2. `version_hash`
/// 3. `source_hash`
/// 4. `flag_hash`
/// 5. `payload_length`
/// 6. `checksum`
///
/// `kUnalignedHeaderSize = 6 * 4 = 24`; aligned to 8-byte pointer size → 24.
pub const V8_HEADER_SIZE_V11: usize = 24usize;

/// V8 `SerializedCodeData` header layout for Node 22 / 24 (V8 ≥ 12.x).
///
/// Identical to [`V8_HEADER_SIZE_V11`] plus an inserted
/// `read_only_snapshot_checksum` field between `flag_hash` and `payload_length`:
/// 1. `magic_number`
/// 2. `version_hash`
/// 3. `source_hash`
/// 4. `flag_hash`
/// 5. `read_only_snapshot_checksum`
/// 6. `payload_length`
/// 7. `checksum`
///
/// `kUnalignedHeaderSize = 7 * 4 = 28`; aligned to 8 → 32.
pub const V8_HEADER_SIZE_V12: usize = 32usize;

/// Maximum plausible payload size (256 MiB) - guards against the
/// `payload_length = 1.6 GiB` confabulations the old parser produced.
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

    /// Map a raw `SerializedCodeData::kMagicNumber` value to the Node major version
    /// whose bundled V8 produced it.
    ///
    /// The high 16 bits are always `0xC0DE`; the low 16 bits encode the V8
    /// minor/build marker. Returns [`Self::Unknown`] if the high bits do not match
    /// or the low marker is not one we recognize.
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

    /// Header layout this V8 version uses.
    ///
    /// `Unknown` defaults to [`HeaderLayout::V12`] because the V12 layout is what
    /// every Node 22+ release ships, and it is the layout the self-describing
    /// fallback in [`parse_bytenode_header`] is most likely to validate on
    /// future V8 releases.
    #[must_use]
    pub const fn header_layout(self) -> HeaderLayout {
        match self {
            Self::Node18 | Self::Node20 => HeaderLayout::V11,
            Self::Node22 | Self::Node24 | Self::Unknown => HeaderLayout::V12,
        }
    }
}

/// Two known V8 `SerializedCodeData` header shapes observed in real `.jsc` data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderLayout {
    /// 24-byte header (Node 18 / 20, V8 ≤ 11.x).
    V11,
    /// 32-byte header with extra `read_only_snapshot_checksum` field (Node 22 / 24, V8 ≥ 12.x).
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
    /// Present only on [`HeaderLayout::V12`] (Node 22+). `None` on V11.
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
    /// The serialized V8 snapshot payload (NOT a flat `BytecodeArray`).
    /// See [`SnapshotDeserializeStatus`] for what can and cannot be derived from it.
    pub payload: Vec<u8>,
}

/// Honest disclosure of what the disrobe pipeline can (and cannot) recover from a
/// parsed `SerializedCodeData` payload for a given V8 version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum SnapshotDeserializeStatus {
    /// V8 version is one we recognize but full snapshot deserialization is not
    /// implemented in disrobe (it would require reimplementing
    /// `v8::internal::Deserializer::ReadObject` for this exact V8 release).
    /// Best-effort string-pool scrape is still available.
    SnapshotDeserializeWall {
        node_version: NodeVersion,
        v8_version_label: &'static str,
        reason: &'static str,
    },
    /// V8 magic high bits matched `0xC0DE` but the low marker is not in our
    /// known table; cannot determine the exact V8 release.
    UnknownV8Marker { magic_low: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrapedConstantPool {
    /// Best-effort recovery: contiguous ASCII / UTF-8 runs of length ≥ `min_run`.
    pub strings: Vec<String>,
    pub min_run: usize,
}

/// Cheap predicate for a V8 `SerializedCodeData` (`.jsc` / bytenode) header.
///
/// Wraps [`parse_bytenode_header`] so the chain detector can sniff a blob
/// without owning the parsed structure.
#[must_use]
pub fn looks_like_bytenode(bytes: &[u8]) -> bool {
    parse_bytenode_header(bytes).is_ok()
}

/// Parse a V8 `SerializedCodeData` header from the start of `bytes`.
///
/// Layout discovery is two-stage:
/// 1. Read the first `u32` magic. If `magic >> 16 != 0xC0DE`, reject (not a V8 code cache).
/// 2. Pick the [`HeaderLayout`] from the recognized low-16-bit marker; if the
///    marker is unrecognized, try both layouts and accept the one whose
///    `kHeaderSize + payload_length == bytes.len()` self-describes correctly.
///
/// Errors are typed via [`Error::OxcParse`] with a concrete reason; no fabrication.
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

/// Parse the full `.jsc` blob: header + the snapshot payload that follows.
///
/// The returned [`BytenodeCacheBody::payload`] is the raw V8 snapshot - see
/// [`snapshot_deserialize_status`] for what disrobe can extract from it.
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

/// Honest recovery status for the snapshot payload of a parsed `.jsc` header.
///
/// disrobe can parse the header and scrape constants (real path); it cannot fully
/// re-emit the original JS function bodies without reimplementing V8's
/// `Deserializer::ReadObject` for this exact V8 release (snapshot-deserialize wall).
#[must_use]
pub fn snapshot_deserialize_status(header: &BytenodeCacheHeader) -> SnapshotDeserializeStatus {
    match header.version_hash.node {
        NodeVersion::Node18 => SnapshotDeserializeStatus::SnapshotDeserializeWall {
            node_version: NodeVersion::Node18,
            v8_version_label: "v10.2",
            reason: WALL_REASON,
        },
        NodeVersion::Node20 => SnapshotDeserializeStatus::SnapshotDeserializeWall {
            node_version: NodeVersion::Node20,
            v8_version_label: "v11.3",
            reason: WALL_REASON,
        },
        NodeVersion::Node22 => SnapshotDeserializeStatus::SnapshotDeserializeWall {
            node_version: NodeVersion::Node22,
            v8_version_label: "v12.4",
            reason: WALL_REASON,
        },
        NodeVersion::Node24 => SnapshotDeserializeStatus::SnapshotDeserializeWall {
            node_version: NodeVersion::Node24,
            v8_version_label: "v13.6",
            reason: WALL_REASON,
        },
        NodeVersion::Unknown => SnapshotDeserializeStatus::UnknownV8Marker {
            magic_low: u16::try_from(header.magic_number & V8_MAGIC_MARKER_MASK).unwrap_or(0u16),
        },
    }
}

const WALL_REASON: &str = "V8 SerializedCodeData payload is a snapshot (Deserializer::ReadObject opcodes \
     referencing SerializerReference / NewObject / RootArray slots), NOT a flat \
     BytecodeArray. Full extraction requires reimplementing the V8 deserializer for \
     this exact V8 release; layout changes between V8 versions. disrobe provides \
     header parse + version detection + best-effort string-pool scrape; \
     full lift is gated behind this wall.";

/// Best-effort scrape of contiguous printable runs from the snapshot payload.
///
/// This is the **REAL** recovery path that works across all V8 versions: V8's
/// `OneByteString` / `TwoByteString` `SeqString` instances are written verbatim into
/// the serialized snapshot. Scraping ASCII runs of length ≥ `min_run` recovers
/// identifiers, property names, and string literals (e.g. `"process"`, `"stdout"`,
/// `"hello "`, `"evalmachine.<anonymous>"`).
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
            wall @ SnapshotDeserializeStatus::SnapshotDeserializeWall { .. } => {
                panic!("expected UnknownV8Marker, got {wall:?}");
            }
        }
    }

    #[test]
    fn snapshot_deserialize_wall_emitted_for_known_versions() {
        let bytes: Vec<u8> = synth_v12_jsc(V8_MAGIC_NODE_24, 0xDC33_8CFA, 32);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("parse");
        match snapshot_deserialize_status(&header) {
            SnapshotDeserializeStatus::SnapshotDeserializeWall {
                node_version,
                v8_version_label,
                reason,
            } => {
                assert_eq!(node_version, NodeVersion::Node24);
                assert_eq!(v8_version_label, "v13.6");
                assert!(reason.contains("snapshot"));
                assert!(reason.contains("Deserializer"));
            }
            unk @ SnapshotDeserializeStatus::UnknownV8Marker { .. } => {
                panic!("expected SnapshotDeserializeWall, got {unk:?}");
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
