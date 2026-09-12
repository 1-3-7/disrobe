use std::collections::BTreeSet;

use disrobe_bytes::read_uleb128_at;
use serde::Serialize;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BlobLeaf {
    Str(String),

    Int(i64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BlobScan {
    pub blob_offset: usize,

    pub blob_len: usize,

    pub leaves: Vec<BlobLeaf>,

    pub strings: BTreeSet<String>,

    pub ints: BTreeSet<i64>,

    pub container_count: u32,
}

const MIN_STRING_RUN: usize = 3;

const MAX_CONTAINER_LEN: u64 = 1 << 24;

const MAX_DEPTH: usize = 64;

const MAX_LEAVES: usize = 200_000;

const MAX_LEAF_BYTES: usize = 1 << 20;

const SCAN_WORK_FACTOR: u64 = 64;

#[must_use]
pub fn scan_constants_blob(image: &[u8]) -> Option<BlobScan> {
    let mut merged: Option<BlobScan> = None;
    let mut cursor: usize = 0usize;
    let mut scan_work: u64 = (image.len() as u64)
        .saturating_mul(SCAN_WORK_FACTOR)
        .max(MAX_LEAF_BYTES as u64);

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
            _ => {
                let horizon: usize = start.saturating_add(MAX_LEAF_BYTES).min(image.len());
                let leading_extent: u64 = image
                    .get(start..horizon)
                    .and_then(|window: &[u8]| window.iter().position(|&b: &u8| b == 0))
                    .map_or((horizon - start) as u64, |zero: usize| zero as u64 + 1);
                scan_work = scan_work.saturating_sub(leading_extent);
                if scan_work == 0 {
                    break;
                }
                cursor = start + 1;
            }
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
                self.push_str(text)?;
                Some(end)
            }

            Tag::TextSingle => {
                let &byte: &u8 = self.image.get(after_tag)?;
                self.push_str(String::from_utf8_lossy(&[byte]).into_owned())?;
                Some(after_tag + 1)
            }

            Tag::BytesZeroTerm => {
                let (_, end): (&[u8], usize) = read_zero_terminated_bytes(self.image, after_tag)?;
                Some(end)
            }

            Tag::TextUtf8LenPrefixed => {
                let (len, after_len): (u64, usize) = read_varint(self.image, after_tag)?;
                if len > MAX_LEAF_BYTES as u64 {
                    return None;
                }
                let end: usize = checked_span(after_len, len)?;
                let slice: &[u8] = self.image.get(after_len..end)?;
                self.push_str(String::from_utf8_lossy(slice).into_owned())?;
                Some(end)
            }

            Tag::BytesLenPrefixed | Tag::BlobData | Tag::ByteArray => {
                let (len, after_len): (u64, usize) = read_varint(self.image, after_tag)?;
                if len > MAX_LEAF_BYTES as u64 {
                    return None;
                }
                let end: usize = checked_span(after_len, len)?;
                let _ = self.image.get(after_len..end)?;
                Some(end)
            }

            Tag::LongPosSmall | Tag::IntPositive => {
                let (value, end): (u64, usize) = read_varint(self.image, after_tag)?;
                self.push_int(i64::try_from(value).ok())?;
                Some(end)
            }
            Tag::LongNegSmall | Tag::IntNegative => {
                let (value, end): (u64, usize) = read_varint(self.image, after_tag)?;
                let signed: Option<i64> = i64::try_from(value).ok().map(|v: i64| -v);
                self.push_int(signed)?;
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
    fn push_str(&mut self, text: String) -> Option<()> {
        if self.leaves.len() >= MAX_LEAVES {
            return None;
        }
        if !text.is_empty() {
            self.strings.insert(text.clone());
        }
        self.leaves.push(BlobLeaf::Str(text));
        Some(())
    }

    #[inline]
    fn push_int(&mut self, value: Option<i64>) -> Option<()> {
        if let Some(v) = value {
            if self.leaves.len() >= MAX_LEAVES {
                return None;
            }
            self.ints.insert(v);
            self.leaves.push(BlobLeaf::Int(v));
        }
        Some(())
    }
}

#[inline]
fn checked_span(start: usize, len: u64) -> Option<usize> {
    let len_usize: usize = usize::try_from(len).ok()?;
    start.checked_add(len_usize)
}

#[inline]
fn read_varint(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let (value, consumed): (u64, usize) = read_uleb128_at(bytes, start).ok()?;
    let end: usize = start.checked_add(consumed)?;
    Some((value, end))
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
    let end_limit: usize = start.checked_add(MAX_LEAF_BYTES)?.min(bytes.len());
    let rel: usize = bytes
        .get(start..end_limit)?
        .iter()
        .position(|&b: &u8| b == 0)?;
    let end: usize = start.checked_add(rel)?;
    Some((bytes.get(start..end)?, end.checked_add(1)?))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn zero_free_string_tag_run_is_work_bounded() {
        let image: Vec<u8> = vec![Tag::AttributeName as u8; 512 * 1024];
        assert!(scan_constants_blob(&image).is_none());
    }

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
    fn varint_nonzero_offset_returns_absolute_end() {
        let encoded: [u8; 4] = [0x00, 0x00, 0xAC, 0x02];
        assert_eq!(read_varint(&encoded, 2), Some((300, 4)));
    }

    #[test]
    fn varint_rejects_overflowing_tenth_byte() {
        let encoded: [u8; 10] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert!(read_varint(&encoded, 0).is_none());
    }

    #[test]
    fn empty_input_yields_none() {
        assert!(scan_constants_blob(&[]).is_none());
    }

    #[test]
    fn oversized_len_prefixed_text_is_rejected_before_allocation() {
        let mut blob: Vec<u8> = vec![Tag::TextUtf8LenPrefixed as u8];
        blob.extend(varint(MAX_LEAF_BYTES as u64 + 1));
        blob.resize(blob.len() + 16, b'a');
        blob.push(Tag::End as u8);
        assert!(walk_blob(&blob, 0).is_none());
    }

    #[test]
    fn excessive_leaf_count_is_rejected() {
        let mut blob: Vec<u8> = vec![Tag::List as u8];
        blob.extend(varint(MAX_LEAVES as u64 + 1));
        for _ in 0..=MAX_LEAVES {
            blob.push(Tag::TextSingle as u8);
            blob.push(b'x');
        }
        blob.push(Tag::End as u8);
        assert!(walk_blob(&blob, 0).is_none());
    }

    #[test]
    fn unterminated_string_scan_is_capped() {
        let mut blob: Vec<u8> = vec![Tag::TextUtf8ZeroTerm as u8];
        blob.resize(MAX_LEAF_BYTES + 32, b'a');
        assert!(walk_blob(&blob, 0).is_none());
    }
}
