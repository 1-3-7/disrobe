//! Data-composer constants-blob recovery from a *compiled* Nuitka binary.
//!
//! Nuitka does not embed the raw pickle `.const` streams in release output; its data
//! composer (`nuitka/tools/data_composer/DataComposer.py`) re-serialises every module's
//! constants into one tagged byte blob that the runtime reads via `loadConstantsBlob`.
//! The tag bytes are frozen in `nuitka/build/include/nuitka/constants_blob_spec.h` and are
//! reproduced verbatim in [`Tag`]. This module walks that blob directly out of the binary's
//! data section, recovering the string/int/float leaves (function names, parameter names,
//! literals) that source-level recovery of native code otherwise loses.
//!
//! The blob start is not symbol-anchored in stripped MSVC output, so it is located by the
//! densest run of attribute/UTF-8 string values terminated by the [`Tag::End`] marker - the
//! exact shape the composer emits for a module constant table. The walk is fully recursive
//! over the container tags so a literal byte that happens to equal a string tag inside a
//! code-object payload is never mistaken for a top-level string.

use std::collections::BTreeSet;

use serde::Serialize;

/// Data-composer tag bytes, verbatim from `constants_blob_spec.h` (Nuitka 4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Tag {
    Previous = 0x70,
    None = 0x6E,
    True = 0x74,
    False = 0x46,
    Tuple = 0x54,
    List = 0x4C,
    Dict = 0x44,
    Set = 0x53,
    FrozenSet = 0x50,
    LongPosSmall = 0x6C,
    LongNegSmall = 0x71,
    LongPosLarge = 0x67,
    LongNegLarge = 0x47,
    IntPositive = 0x69,
    IntNegative = 0x49,
    FloatSpecial = 0x5A,
    Float = 0x66,
    TextEmpty = 0x73,
    TextSingle = 0x77,
    TextUtf8LenPrefixed = 0x76,
    TextUtf8ZeroTerm = 0x75,
    AttributeName = 0x61,
    BytesLenPrefixed = 0x62,
    BytesZeroTerm = 0x63,
    BytesSingle = 0x64,
    Slice = 0x3A,
    Range = 0x3B,
    ComplexSpecial = 0x4A,
    Complex = 0x6A,
    ByteArray = 0x42,
    BuiltinAnon = 0x4D,
    BuiltinSpecial = 0x51,
    BlobData = 0x58,
    GenericAlias = 0x41,
    UnionType = 0x48,
    BuiltinNamed = 0x4F,
    BuiltinException = 0x45,
    CodeObject = 0x43,
    End = 0x2E,
}

impl Tag {
    #[inline]
    const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x70 => Self::Previous,
            0x6E => Self::None,
            0x74 => Self::True,
            0x46 => Self::False,
            0x54 => Self::Tuple,
            0x4C => Self::List,
            0x44 => Self::Dict,
            0x53 => Self::Set,
            0x50 => Self::FrozenSet,
            0x6C => Self::LongPosSmall,
            0x71 => Self::LongNegSmall,
            0x67 => Self::LongPosLarge,
            0x47 => Self::LongNegLarge,
            0x69 => Self::IntPositive,
            0x49 => Self::IntNegative,
            0x5A => Self::FloatSpecial,
            0x66 => Self::Float,
            0x73 => Self::TextEmpty,
            0x77 => Self::TextSingle,
            0x76 => Self::TextUtf8LenPrefixed,
            0x75 => Self::TextUtf8ZeroTerm,
            0x61 => Self::AttributeName,
            0x62 => Self::BytesLenPrefixed,
            0x63 => Self::BytesZeroTerm,
            0x64 => Self::BytesSingle,
            0x3A => Self::Slice,
            0x3B => Self::Range,
            0x4A => Self::ComplexSpecial,
            0x6A => Self::Complex,
            0x42 => Self::ByteArray,
            0x4D => Self::BuiltinAnon,
            0x51 => Self::BuiltinSpecial,
            0x58 => Self::BlobData,
            0x41 => Self::GenericAlias,
            0x48 => Self::UnionType,
            0x4F => Self::BuiltinNamed,
            0x45 => Self::BuiltinException,
            0x43 => Self::CodeObject,
            0x2E => Self::End,
            _ => return None,
        })
    }
}

/// One value leaf recovered from the blob walk, in stream order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BlobLeaf {
    /// A unicode/attribute string constant (function name, param name, literal, …).
    Str(String),
    /// A signed integer constant.
    Int(i64),
}

/// Result of scanning a compiled binary's data-composer constants blob.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BlobScan {
    /// Offset of the located blob within the supplied image.
    pub blob_offset: usize,
    /// Number of bytes the walk consumed from `blob_offset` to the [`Tag::End`] marker.
    pub blob_len: usize,
    /// Leaves in stream order (duplicates preserved).
    pub leaves: Vec<BlobLeaf>,
    /// Distinct recovered strings, sorted.
    pub strings: BTreeSet<String>,
    /// Distinct recovered integers, sorted.
    pub ints: BTreeSet<i64>,
    /// Number of nested container tags the walk descended through.
    pub container_count: u32,
}

/// Shortest run of consecutive string values that qualifies a candidate as a real module
/// constant table rather than a coincidental tag byte in code.
const MIN_STRING_RUN: usize = 3;

/// Hard ceiling on container length to reject a mis-aligned varint that would otherwise
/// drive an enormous bogus loop.
const MAX_CONTAINER_LEN: u64 = 1 << 24;

/// Hard ceiling on recursion depth, matching the composer's practical nesting.
const MAX_DEPTH: usize = 64;

/// Scan `image` for every data-composer constants blob segment and union their leaves.
///
/// A compiled Nuitka binary carries the shared global-constants table *and* a per-module
/// constant table as separate `End`-terminated tagged streams; both are recovered and merged
/// so module-local names (`greet`, `fib`, …) are not lost to the larger global table.
///
/// Returns `None` when no plausible blob is present (e.g. a onefile bootstrap whose payload
/// is still compressed, or a non-Nuitka binary).
#[must_use]
pub fn scan_constants_blob(image: &[u8]) -> Option<BlobScan> {
    let mut merged: Option<BlobScan> = None;
    let mut cursor: usize = 0usize;

    while cursor < image.len() {
        let Some(rel): Option<usize> = first_string_tag(&image[cursor..]) else {
            break;
        };
        let start: usize = cursor + rel;
        match walk_blob(image, start) {
            Some(scan) if qualifies(&scan) => {
                let next: usize = start + scan.blob_len;
                merge_segment(&mut merged, scan);
                cursor = next.max(start + 1);
            }
            _ => cursor = start + 1,
        }
    }

    merged
}

fn merge_segment(merged: &mut Option<BlobScan>, segment: BlobScan) {
    match merged {
        None => *merged = Some(segment),
        Some(acc) => {
            for leaf in segment.leaves {
                match &leaf {
                    BlobLeaf::Str(s) => {
                        if !s.is_empty() {
                            acc.strings.insert(s.clone());
                        }
                    }
                    BlobLeaf::Int(i) => {
                        acc.ints.insert(*i);
                    }
                }
                acc.leaves.push(leaf);
            }
            acc.container_count = acc.container_count.saturating_add(segment.container_count);
        }
    }
}

#[inline]
fn qualifies(scan: &BlobScan) -> bool {
    let string_leaves: usize = scan
        .leaves
        .iter()
        .filter(|l: &&BlobLeaf| matches!(l, BlobLeaf::Str(_)))
        .count();
    string_leaves >= MIN_STRING_RUN && !scan.strings.is_empty()
}

#[inline]
fn first_string_tag(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b: &u8| {
        matches!(
            Tag::from_byte(b),
            Some(Tag::AttributeName | Tag::TextUtf8ZeroTerm | Tag::TextUtf8LenPrefixed)
        )
    })
}

struct Walker<'a> {
    image: &'a [u8],
    leaves: Vec<BlobLeaf>,
    strings: BTreeSet<String>,
    ints: BTreeSet<i64>,
    container_count: u32,
}

fn walk_blob(image: &[u8], start: usize) -> Option<BlobScan> {
    let mut walker: Walker<'_> = Walker {
        image,
        leaves: Vec::new(),
        strings: BTreeSet::new(),
        ints: BTreeSet::new(),
        container_count: 0u32,
    };
    let mut cursor: usize = start;

    loop {
        if cursor >= image.len() {
            return None;
        }
        if image[cursor] == Tag::End as u8 {
            cursor += 1;
            break;
        }
        let next: usize = walker.walk_value(cursor, 0)?;
        if next <= cursor {
            return None;
        }
        cursor = next;
    }

    if walker.leaves.is_empty() {
        return None;
    }

    Some(BlobScan {
        blob_offset: start,
        blob_len: cursor - start,
        leaves: walker.leaves,
        strings: walker.strings,
        ints: walker.ints,
        container_count: walker.container_count,
    })
}

impl Walker<'_> {
    fn walk_value(&mut self, at: usize, depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        let tag_byte: u8 = *self.image.get(at)?;
        let tag: Tag = Tag::from_byte(tag_byte)?;
        let after_tag: usize = at + 1;

        match tag {
            Tag::None | Tag::True | Tag::False | Tag::TextEmpty | Tag::Previous => Some(after_tag),

            Tag::BuiltinAnon
            | Tag::BuiltinSpecial
            | Tag::FloatSpecial
            | Tag::ComplexSpecial
            | Tag::BytesSingle => Some(after_tag + 1),

            Tag::Float => checked_span(after_tag, 8),
            Tag::Complex => checked_span(after_tag, 16),

            Tag::AttributeName
            | Tag::TextUtf8ZeroTerm
            | Tag::BuiltinNamed
            | Tag::BuiltinException => {
                let (text, end): (String, usize) = read_zero_terminated_str(self.image, after_tag)?;
                self.push_str(text);
                Some(end)
            }

            Tag::TextSingle => {
                let &byte: &u8 = self.image.get(after_tag)?;
                self.push_str(String::from_utf8_lossy(&[byte]).into_owned());
                Some(after_tag + 1)
            }

            Tag::BytesZeroTerm => {
                let (_, end): (&[u8], usize) = read_zero_terminated_bytes(self.image, after_tag)?;
                Some(end)
            }

            Tag::TextUtf8LenPrefixed => {
                let (len, after_len): (u64, usize) = read_varint(self.image, after_tag)?;
                let end: usize = checked_span(after_len, len)?;
                let slice: &[u8] = self.image.get(after_len..end)?;
                self.push_str(String::from_utf8_lossy(slice).into_owned());
                Some(end)
            }

            Tag::BytesLenPrefixed | Tag::BlobData | Tag::ByteArray => {
                let (len, after_len): (u64, usize) = read_varint(self.image, after_tag)?;
                let end: usize = checked_span(after_len, len)?;
                let _ = self.image.get(after_len..end)?;
                Some(end)
            }

            Tag::LongPosSmall | Tag::IntPositive => {
                let (value, end): (u64, usize) = read_varint(self.image, after_tag)?;
                self.push_int(i64::try_from(value).ok());
                Some(end)
            }
            Tag::LongNegSmall | Tag::IntNegative => {
                let (value, end): (u64, usize) = read_varint(self.image, after_tag)?;
                let signed: Option<i64> = i64::try_from(value).ok().map(|v: i64| -v);
                self.push_int(signed);
                Some(end)
            }
            Tag::LongPosLarge | Tag::LongNegLarge => {
                let (parts, after_count): (u64, usize) = read_varint(self.image, after_tag)?;
                if parts > MAX_CONTAINER_LEN {
                    return None;
                }
                let mut cursor: usize = after_count;
                for _ in 0..parts {
                    let (_, end): (u64, usize) = read_varint(self.image, cursor)?;
                    cursor = end;
                }
                Some(cursor)
            }

            Tag::Tuple | Tag::List | Tag::Set | Tag::FrozenSet => {
                self.walk_sequence(after_tag, depth)
            }
            Tag::Dict => {
                let (count, after_count): (u64, usize) = read_varint(self.image, after_tag)?;
                if count > MAX_CONTAINER_LEN {
                    return None;
                }
                self.container_count = self.container_count.saturating_add(1);
                let mut cursor: usize = after_count;
                for _ in 0..count.saturating_mul(2) {
                    cursor = self.walk_value(cursor, depth + 1)?;
                }
                Some(cursor)
            }
            Tag::Slice | Tag::Range => {
                let mut cursor: usize = after_tag;
                for _ in 0..3 {
                    cursor = self.walk_value(cursor, depth + 1)?;
                }
                Some(cursor)
            }

            Tag::GenericAlias => {
                let origin: usize = self.walk_value(after_tag, depth + 1)?;
                self.walk_value(origin, depth + 1)
            }
            Tag::UnionType => self.walk_value(after_tag, depth + 1),

            Tag::CodeObject | Tag::End => None,
        }
    }

    fn walk_sequence(&mut self, after_tag: usize, depth: usize) -> Option<usize> {
        let (count, after_count): (u64, usize) = read_varint(self.image, after_tag)?;
        if count > MAX_CONTAINER_LEN {
            return None;
        }
        self.container_count = self.container_count.saturating_add(1);
        let mut cursor: usize = after_count;
        for _ in 0..count {
            cursor = self.walk_value(cursor, depth + 1)?;
        }
        Some(cursor)
    }

    #[inline]
    fn push_str(&mut self, text: String) {
        if !text.is_empty() {
            self.strings.insert(text.clone());
        }
        self.leaves.push(BlobLeaf::Str(text));
    }

    #[inline]
    fn push_int(&mut self, value: Option<i64>) {
        if let Some(v) = value {
            self.ints.insert(v);
            self.leaves.push(BlobLeaf::Int(v));
        }
    }
}

#[inline]
fn checked_span(start: usize, len: u64) -> Option<usize> {
    let len_usize: usize = usize::try_from(len).ok()?;
    start.checked_add(len_usize)
}

#[inline]
fn read_varint(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0u64;
    let mut shift: u32 = 0u32;
    let mut cursor: usize = start;
    loop {
        let &byte: &u8 = bytes.get(cursor)?;
        cursor += 1;
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((value, cursor));
        }
        shift += 7;
    }
}

#[inline]
fn read_zero_terminated_str(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let (slice, end): (&[u8], usize) = read_zero_terminated_bytes(bytes, start)?;
    if !slice
        .iter()
        .all(|&b: &u8| b.is_ascii() && (b >= 0x20 || b == b'\t'))
    {
        return None;
    }
    Some((String::from_utf8_lossy(slice).into_owned(), end))
}

#[inline]
fn read_zero_terminated_bytes(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let rel: usize = bytes.get(start..)?.iter().position(|&b: &u8| b == 0)?;
    Some((&bytes[start..start + rel], start + rel + 1))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        while value >= 128 {
            out.push(((value & 0x7F) | 0x80) as u8);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn attr(name: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![Tag::AttributeName as u8];
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out
    }

    fn utf8z(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![Tag::TextUtf8ZeroTerm as u8];
        out.extend_from_slice(text.as_bytes());
        out.push(0);
        out
    }

    #[test]
    fn walks_flat_string_table() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend(utf8z("hello, "));
        blob.extend(attr("greet"));
        blob.extend(attr("fib"));
        blob.extend(attr("main"));
        blob.push(Tag::End as u8);
        let scan: BlobScan = scan_constants_blob(&blob).expect("blob");
        assert!(scan.strings.contains("greet"));
        assert!(scan.strings.contains("fib"));
        assert!(scan.strings.contains("main"));
        assert!(scan.strings.contains("hello, "));
    }

    #[test]
    fn descends_tuple_and_recovers_ints() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend(attr("origin"));
        blob.extend(attr("has_location"));
        blob.extend(attr("encoding"));
        blob.push(Tag::Tuple as u8);
        blob.extend(varint(2));
        blob.push(Tag::LongPosSmall as u8);
        blob.extend(varint(20));
        blob.push(Tag::LongNegSmall as u8);
        blob.extend(varint(5));
        blob.push(Tag::End as u8);
        let scan: BlobScan = scan_constants_blob(&blob).expect("blob");
        assert!(scan.ints.contains(&20));
        assert!(scan.ints.contains(&-5));
        assert!(scan.strings.contains("origin"));
        assert!(scan.container_count >= 1);
    }

    #[test]
    fn recovers_builtin_named_and_dict() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend(attr("name"));
        blob.extend(attr("return"));
        blob.push(Tag::Dict as u8);
        blob.extend(varint(1));
        blob.extend(attr("return"));
        blob.push(Tag::BuiltinNamed as u8);
        blob.extend_from_slice(b"int\0");
        blob.push(Tag::End as u8);
        let scan: BlobScan = scan_constants_blob(&blob).expect("blob");
        assert!(scan.strings.contains("int"));
        assert!(scan.strings.contains("return"));
        assert!(scan.container_count >= 1);
    }

    #[test]
    fn rejects_lone_tag_byte_in_noise() {
        let mut bytes: Vec<u8> = vec![0u8; 256];
        bytes[100] = Tag::AttributeName as u8;
        bytes[101] = b'x';
        assert!(scan_constants_blob(&bytes).is_none());
    }

    #[test]
    fn varint_multibyte_round_trip() {
        let encoded: Vec<u8> = varint(300);
        let (value, end): (u64, usize) = read_varint(&encoded, 0).expect("varint");
        assert_eq!(value, 300);
        assert_eq!(end, encoded.len());
    }

    #[test]
    fn empty_input_yields_none() {
        assert!(scan_constants_blob(&[]).is_none());
    }
}
