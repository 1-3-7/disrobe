use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::object::Object;
use crate::version::PyVersion;

extern crate alloc;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefEntry {
    pub index: u32,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub depth: u16,
    pub tag: u8,
    pub kind: RefKind,
    pub preview: String,
}

impl fmt::Debug for RefEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefEntry")
            .field("index", &self.index)
            .field("byte_offset", &self.byte_offset)
            .field("byte_length", &self.byte_length)
            .field("depth", &self.depth)
            .field("tag", &format_args!("0x{:02x}", self.tag))
            .field("kind", &self.kind)
            .field("preview", &self.preview)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RefKind {
    Null,
    None,
    True,
    False,
    Ellipsis,
    StopIteration,
    Int,
    Int64,
    Long,
    Float,
    Complex,
    Bytes,
    String,
    InternedString,
    ShortAscii,
    ShortAsciiInterned,
    Tuple,
    List,
    Set,
    FrozenSet,
    Dict,
    FrozenDict,
    Code,
    Slice,
    Ref,
    Unknown,
}

impl RefKind {
    #[must_use]
    pub const fn from_tag(tag: u8) -> Self {
        match tag {
            b'0' => Self::Null,
            b'N' => Self::None,
            b'T' => Self::True,
            b'F' => Self::False,
            b'.' => Self::Ellipsis,
            b'S' => Self::StopIteration,
            b'i' => Self::Int,
            b'I' => Self::Int64,
            b'l' => Self::Long,
            b'g' | b'f' => Self::Float,
            b'y' | b'x' => Self::Complex,
            b's' => Self::Bytes,
            b'a' | b'u' => Self::String,
            b'A' | b't' => Self::InternedString,
            b'z' => Self::ShortAscii,
            b'Z' => Self::ShortAsciiInterned,
            b'(' | b')' => Self::Tuple,
            b'[' => Self::List,
            b'<' => Self::Set,
            b'>' => Self::FrozenSet,
            b'{' => Self::Dict,
            b'}' => Self::FrozenDict,
            b'c' => Self::Code,
            b':' => Self::Slice,
            b'r' => Self::Ref,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefTableDump {
    pub entries: Vec<RefEntry>,
    pub total_bytes: usize,
    pub max_depth_observed: u16,
    pub by_kind: BTreeMap<RefKind, u32>,
}

impl RefTableDump {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
            total_bytes: 0,
            max_depth_observed: 0,
            by_kind: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn referenced_indices(&self) -> BTreeSet<u32> {
        self.entries
            .iter()
            .filter(|e| matches!(e.kind, RefKind::Ref))
            .filter_map(|e| e.preview.parse::<u32>().ok())
            .collect()
    }

    pub fn ref_allocations(&self) -> impl Iterator<Item = &RefEntry> {
        self.entries.iter().filter(|e| e.index != u32::MAX)
    }

    #[must_use]
    pub fn unused_refs(&self) -> BTreeSet<u32> {
        let referenced: BTreeSet<u32> = self.referenced_indices();
        let defined: BTreeSet<u32> = self.ref_allocations().map(|e| e.index).collect();
        defined.difference(&referenced).copied().collect()
    }

    pub(crate) fn finalize(&mut self, total_bytes: usize) {
        self.total_bytes = total_bytes;
        let mut max_depth: u16 = 0u16;
        let mut by_kind: BTreeMap<RefKind, u32> = BTreeMap::new();
        for entry in &self.entries {
            if entry.depth > max_depth {
                max_depth = entry.depth;
            }
            *by_kind.entry(entry.kind).or_default() += 1;
        }
        self.max_depth_observed = max_depth;
        self.by_kind = by_kind;
    }
}

pub fn dump_reftable(data: &[u8], version: PyVersion) -> Result<(Object, RefTableDump)> {
    crate::reader::load_with_reftable(data, version)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::writer::dump;

    const FLAG_REF: u8 = 0x80;

    #[test]
    fn dumps_single_ref_for_interned_string() {
        let mut data: Vec<u8> = vec![b'Z' | FLAG_REF, 5];
        data.extend(b"hello");
        let (obj, table): (Object, RefTableDump) = dump_reftable(&data, PyVersion::PY312).unwrap();
        assert!(matches!(obj, Object::ShortAscii { .. }));
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].kind, RefKind::ShortAsciiInterned);
        assert_eq!(table.entries[0].preview, "hello");
    }

    #[test]
    fn referenced_indices_track_back_refs() {
        let mut data: Vec<u8> = vec![b')', 2, b'Z' | FLAG_REF, 6];
        data.extend(b"shared");
        data.push(b'r');
        data.extend(0u32.to_le_bytes());
        let (_obj, table): (Object, RefTableDump) = dump_reftable(&data, PyVersion::PY312).unwrap();
        let referenced: BTreeSet<u32> = table.referenced_indices();
        assert!(referenced.contains(&0));
    }

    #[test]
    fn by_kind_aggregates_counts() {
        let payload: Object = Object::Tuple(vec![
            Object::String {
                value: "a".to_owned(),
                interned: true,
            },
            Object::String {
                value: "b".to_owned(),
                interned: true,
            },
        ]);
        let bytes: Vec<u8> = dump(&payload, PyVersion::PY312).unwrap();
        let (_obj, table): (Object, RefTableDump) =
            dump_reftable(&bytes, PyVersion::PY312).unwrap();
        let interned_count: u32 = table
            .by_kind
            .get(&RefKind::InternedString)
            .copied()
            .unwrap_or(0);
        assert_eq!(interned_count, 2);
    }

    #[test]
    fn unused_refs_reports_unreferenced_indices() {
        let mut data: Vec<u8> = vec![b'Z' | FLAG_REF, 3];
        data.extend(b"foo");
        let (_obj, table): (Object, RefTableDump) = dump_reftable(&data, PyVersion::PY312).unwrap();
        let unused: BTreeSet<u32> = table.unused_refs();
        assert!(unused.contains(&0));
    }

    #[test]
    fn empty_input_errors_cleanly() {
        let err: crate::error::Error = dump_reftable(b"", PyVersion::PY312).unwrap_err();
        assert!(matches!(err, crate::error::Error::Eof { .. }));
    }

    #[test]
    fn total_bytes_matches_consumed() {
        let mut data: Vec<u8> = vec![b'Z' | FLAG_REF, 5];
        data.extend(b"hello");
        let (_obj, table): (Object, RefTableDump) = dump_reftable(&data, PyVersion::PY312).unwrap();
        assert_eq!(table.total_bytes, data.len());
    }

    #[test]
    fn refkind_from_tag_matches_codec_tags() {
        assert_eq!(RefKind::from_tag(b'N'), RefKind::None);
        assert_eq!(RefKind::from_tag(b'i'), RefKind::Int);
        assert_eq!(RefKind::from_tag(b')'), RefKind::Tuple);
        assert_eq!(RefKind::from_tag(b'Z'), RefKind::ShortAsciiInterned);
        assert_eq!(RefKind::from_tag(b'\0'), RefKind::Unknown);
    }

    #[test]
    fn byte_offsets_increase_monotonically() {
        let payload: Object = Object::Tuple(vec![
            Object::String {
                value: "a".to_owned(),
                interned: true,
            },
            Object::String {
                value: "b".to_owned(),
                interned: true,
            },
        ]);
        let bytes: Vec<u8> = dump(&payload, PyVersion::PY312).unwrap();
        let (_obj, table): (Object, RefTableDump) =
            dump_reftable(&bytes, PyVersion::PY312).unwrap();
        let offsets: Vec<usize> = table.entries.iter().map(|e| e.byte_offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] <= w[1]));
    }
}
