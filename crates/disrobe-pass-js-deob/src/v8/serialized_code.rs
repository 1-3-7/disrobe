use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::bytenode::NodeVersion;

pub const STRING_RECORD_TAG: u8 = 0x52u8;

pub const STRING_MAP_SEQ_ONE_BYTE: u8 = 0x61u8;

pub const STRING_MAP_INTERNALIZED: u8 = 0x63u8;

pub const SFI_MARKER: [u8; 3] = [0x24u8, 0x54u8, 0x03u8];

pub const STRING_RECORD_PREAMBLE: usize = 10usize;

pub const MAX_STRING_LEN: u32 = 1u32 << 24u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringClass {
    SeqOneByte,
    Internalized,
}

impl StringClass {
    #[must_use]
    pub const fn from_map_byte(byte: u8) -> Option<Self> {
        match byte {
            STRING_MAP_SEQ_ONE_BYTE => Some(Self::SeqOneByte),
            STRING_MAP_INTERNALIZED => Some(Self::Internalized),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SeqOneByte => "seq-one-byte",
            Self::Internalized => "internalized",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FramedString {
    pub payload_offset: usize,
    pub class: StringClass,
    pub raw_hash: u32,
    pub byte_length: u32,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralRecovery {
    pub node_version: NodeVersion,
    pub framed_strings: Vec<FramedString>,
    pub shared_function_info_markers: usize,
    pub recovered_byte_total: usize,
    pub lossy_notes: Vec<String>,
}

impl StructuralRecovery {
    #[must_use]
    pub fn function_name_candidates(&self) -> Vec<&str> {
        self.framed_strings
            .iter()
            .filter(|s: &&FramedString| s.class == StringClass::SeqOneByte)
            .map(|s: &FramedString| s.value.as_str())
            .collect()
    }

    #[must_use]
    pub fn string_literal_candidates(&self) -> Vec<&str> {
        self.framed_strings
            .iter()
            .filter(|s: &&FramedString| s.class == StringClass::Internalized)
            .map(|s: &FramedString| s.value.as_str())
            .collect()
    }
}

const LOSSY_INTERNALIZED_ROOTS: &str = "user-defined identifiers, property names and string literals are serialized inline in the \
     object graph (kInternalizedString / SeqOneByteString in each function's constant-pool \
     FixedArray) and code_serializer::parse_code_serializer_graph reconstructs each function's pool \
     and links them, so they are recovered as readable names (graded byte-exact against \
     node --print-bytecode). The only residue is a small set of common builtin/single-character \
     root strings (e.g. length, push, console, log, \"!\") that V8 serializes as RootArray / \
     ReadOnlyHeapRef indices; these resolve through the pinned per-release root-name table, and a \
     root string from a V8 build whose table is not pinned stays an index (reported honestly, not \
     guessed)";

const LOSSY_LAZY_BODIES: &str = "lazily-compiled inner functions have no BytecodeArray in the .jsc until first runtime call; \
     only eagerly-compiled (top-level + referenced) bodies are present";

const STRING_SCRAPE_IS_A_FALLBACK: &str = "this string scrape is a version-agnostic fallback; for the node-24 / v8-13.6 stream, \
     code_serializer::parse_code_serializer_graph walks the object graph and recovers each \
     BytecodeArray's inline bytecode byte-exact (validated against node --print-bytecode)";

#[must_use]
pub fn recover_structure(payload: &[u8], node: NodeVersion) -> StructuralRecovery {
    let framed_strings: Vec<FramedString> = extract_framed_strings(payload);
    let shared_function_info_markers: usize = count_sfi_markers(payload);
    let recovered_byte_total: usize = framed_strings
        .iter()
        .map(|s: &FramedString| s.value.len())
        .sum();
    StructuralRecovery {
        node_version: node,
        framed_strings,
        shared_function_info_markers,
        recovered_byte_total,
        lossy_notes: vec![
            LOSSY_INTERNALIZED_ROOTS.to_owned(),
            LOSSY_LAZY_BODIES.to_owned(),
            STRING_SCRAPE_IS_A_FALLBACK.to_owned(),
        ],
    }
}

#[must_use]
pub fn extract_framed_strings(payload: &[u8]) -> Vec<FramedString> {
    let mut out: Vec<FramedString> = Vec::new();
    let mut seen: BTreeSet<(usize, String)> = BTreeSet::new();
    let len: usize = payload.len();
    let mut i: usize = 0usize;
    while i + STRING_RECORD_PREAMBLE < len {
        if payload[i] != STRING_RECORD_TAG {
            i += 1usize;
            continue;
        }
        let Some(class): Option<StringClass> = StringClass::from_map_byte(payload[i + 1usize])
        else {
            i += 1usize;
            continue;
        };
        let raw_hash: u32 = read_u32_le(payload, i + 2usize);
        let byte_length: u32 = read_u32_le(payload, i + 6usize);
        if byte_length == 0u32 || byte_length >= MAX_STRING_LEN {
            i += 1usize;
            continue;
        }
        let start: usize = i + STRING_RECORD_PREAMBLE;
        let end: usize = start.saturating_add(byte_length as usize);
        if end > len {
            i += 1usize;
            continue;
        }
        let raw: &[u8] = &payload[start..end];
        let Some(value): Option<String> = decode_one_byte_string(raw) else {
            i += 1usize;
            continue;
        };
        let key: (usize, String) = (i, value.clone());
        if seen.insert(key) {
            out.push(FramedString {
                payload_offset: i,
                class,
                raw_hash,
                byte_length,
                value,
            });
        }
        i = end;
    }
    out
}

#[must_use]
pub fn count_sfi_markers(payload: &[u8]) -> usize {
    if payload.len() < SFI_MARKER.len() {
        return 0usize;
    }
    let mut count: usize = 0usize;
    let last: usize = payload.len() - SFI_MARKER.len();
    let mut i: usize = 0usize;
    while i <= last {
        if payload[i] == SFI_MARKER[0]
            && payload[i + 1usize] == SFI_MARKER[1]
            && payload[i + 2usize] == SFI_MARKER[2]
        {
            count += 1usize;
            i += SFI_MARKER.len();
        } else {
            i += 1usize;
        }
    }
    count
}

fn decode_one_byte_string(raw: &[u8]) -> Option<String> {
    let printable: bool = raw
        .iter()
        .all(|&b: &u8| matches!(b, 0x09u8..=0x0Du8 | 0x20u8..=0x7Eu8));
    if !printable {
        return None;
    }
    Some(raw.iter().map(|&b: &u8| b as char).collect())
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    if offset + 4usize > bytes.len() {
        return 0u32;
    }
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1usize],
        bytes[offset + 2usize],
        bytes[offset + 3usize],
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn framed(class: u8, hash: u32, value: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.push(STRING_RECORD_TAG);
        out.push(class);
        out.extend_from_slice(&hash.to_le_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn extracts_seq_one_byte_and_internalized_records() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&[0x00u8, 0x01u8, 0x02u8]);
        payload.extend(framed(STRING_MAP_SEQ_ONE_BYTE, 0x7AC6_5CEE, b"greet"));
        payload.extend_from_slice(&[0xFFu8, 0xFEu8]);
        payload.extend(framed(STRING_MAP_INTERNALIZED, 0x32FC_D0C6, b"evalmachine"));
        let strings: Vec<FramedString> = extract_framed_strings(&payload);
        assert_eq!(strings.len(), 2usize);
        assert_eq!(strings[0].value, "greet");
        assert_eq!(strings[0].class, StringClass::SeqOneByte);
        assert_eq!(strings[0].raw_hash, 0x7AC6_5CEE);
        assert_eq!(strings[0].byte_length, 5u32);
        assert_eq!(strings[1].value, "evalmachine");
        assert_eq!(strings[1].class, StringClass::Internalized);
    }

    #[test]
    fn ignores_zero_and_oversized_lengths() {
        let mut payload: Vec<u8> = framed(STRING_MAP_SEQ_ONE_BYTE, 0u32, b"");
        payload.extend_from_slice(b"junk");
        let strings: Vec<FramedString> = extract_framed_strings(&payload);
        assert!(strings.is_empty());
    }

    #[test]
    fn rejects_record_running_past_end() {
        let mut payload: Vec<u8> = Vec::new();
        payload.push(STRING_RECORD_TAG);
        payload.push(STRING_MAP_SEQ_ONE_BYTE);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&100u32.to_le_bytes());
        payload.extend_from_slice(b"short");
        let strings: Vec<FramedString> = extract_framed_strings(&payload);
        assert!(strings.is_empty());
    }

    #[test]
    fn rejects_non_printable_string_body() {
        let payload: Vec<u8> = framed(STRING_MAP_SEQ_ONE_BYTE, 0u32, &[0x01u8, 0x02u8, 0x03u8]);
        let strings: Vec<FramedString> = extract_framed_strings(&payload);
        assert!(strings.is_empty());
    }

    #[test]
    fn counts_non_overlapping_sfi_markers() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&SFI_MARKER);
        payload.extend_from_slice(&[0xAAu8; 5]);
        payload.extend_from_slice(&SFI_MARKER);
        assert_eq!(count_sfi_markers(&payload), 2usize);
    }

    #[test]
    fn structural_recovery_partitions_names_and_literals() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend(framed(STRING_MAP_SEQ_ONE_BYTE, 0u32, b"compute"));
        payload.extend(framed(STRING_MAP_INTERNALIZED, 0u32, b"welcome to disrobe"));
        payload.extend_from_slice(&SFI_MARKER);
        let recovery: StructuralRecovery = recover_structure(&payload, NodeVersion::Node24);
        assert_eq!(recovery.function_name_candidates(), vec!["compute"]);
        assert_eq!(
            recovery.string_literal_candidates(),
            vec!["welcome to disrobe"]
        );
        assert_eq!(recovery.shared_function_info_markers, 1usize);
        assert_eq!(recovery.node_version, NodeVersion::Node24);
        assert!(!recovery.lossy_notes.is_empty());
    }
}
