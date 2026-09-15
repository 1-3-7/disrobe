use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::reader::Reader;

pub const ETF_MAGIC: u8 = 131;

pub const TAG_NEW_FLOAT: u8 = 70;
pub const TAG_BIT_BINARY: u8 = 77;
pub const TAG_NEW_PID: u8 = 88;
pub const TAG_NEWER_REFERENCE: u8 = 90;
pub const TAG_SMALL_INTEGER: u8 = 97;
pub const TAG_INTEGER: u8 = 98;
pub const TAG_FLOAT_STRING: u8 = 99;
pub const TAG_ATOM_DEPRECATED: u8 = 100;
pub const TAG_SMALL_TUPLE: u8 = 104;
pub const TAG_LARGE_TUPLE: u8 = 105;
pub const TAG_NIL: u8 = 106;
pub const TAG_STRING: u8 = 107;
pub const TAG_LIST: u8 = 108;
pub const TAG_BINARY: u8 = 109;
pub const TAG_SMALL_BIG: u8 = 110;
pub const TAG_LARGE_BIG: u8 = 111;
pub const TAG_SMALL_ATOM_DEPRECATED: u8 = 115;
pub const TAG_MAP: u8 = 116;
pub const TAG_ATOM_UTF8: u8 = 118;
pub const TAG_SMALL_ATOM_UTF8: u8 = 119;
pub const TAG_EXPORT: u8 = 113;
pub const TAG_COMPRESSED: u8 = 80;

pub(crate) const MAX_ETF_INFLATE: usize = 256 * 1024 * 1024;
const MAX_ATOM_SCALARS: usize = 255;
const MAX_DEPRECATED_ATOM_LATIN1_CHARS: usize = 255;
const MAX_ETF_DEPTH: usize = 500;
const MAX_ETF_CONTAINER_PREALLOC: usize = 1 << 16;
const MIN_TERM_TAG_BYTES: usize = 1;
const MIN_MAP_PAIR_BYTES: usize = 2;
const REFERENCE_ID_BYTES: usize = 4;

pub(crate) fn decode_atom_utf8(bytes: &[u8], index: u32) -> Result<String> {
    let atom: &str = core::str::from_utf8(bytes).map_err(|_| Error::BadAtomUtf8 { index })?;
    let scalars: usize = atom.chars().count();
    if scalars > MAX_ATOM_SCALARS {
        return Err(Error::AtomTooLong {
            index,
            scalars,
            limit: MAX_ATOM_SCALARS,
        });
    }
    Ok(atom.to_owned())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Term {
    SmallInt(u8),
    Int(i32),
    BigInt {
        sign: u8,
        magnitude_le: Vec<u8>,
    },
    Float(f64),
    Atom(String),
    Tuple(Vec<Term>),
    Nil,
    String(Vec<u8>),
    List {
        elements: Vec<Term>,
        tail: Box<Term>,
    },
    Binary(Vec<u8>),
    BitBinary {
        bits: u8,
        data: Vec<u8>,
    },
    Map(BTreeMap<String, Term>),
    MapMixed(Vec<(Term, Term)>),
    Pid {
        node: String,
        id: u32,
        serial: u32,
        creation: u32,
    },
    Reference {
        node: String,
        creation: u32,
        ids: Vec<u32>,
    },
    Export {
        module: String,
        function: String,
        arity: u32,
    },
}

impl Term {
    #[must_use]
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Self::Atom(s) => Some(s.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_tuple(&self) -> Option<&[Self]> {
        match self {
            Self::Tuple(t) => Some(t.as_slice()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_list(&self) -> Option<&[Self]> {
        match self {
            Self::List { elements, tail } if matches!(**tail, Self::Nil) => {
                Some(elements.as_slice())
            }
            Self::Nil => Some(&[]),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_map(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<String> {
        match self {
            Self::Binary(b) => core::str::from_utf8(b).ok().map(str::to_owned),
            Self::String(b) => core::str::from_utf8(b).ok().map(str::to_owned),
            Self::Atom(a) => Some(a.clone()),
            _ => None,
        }
    }
}

pub fn decode_etf(buf: &[u8]) -> Result<Term> {
    let mut reader: Reader<'_> = Reader::new(buf);
    let magic: u8 = reader.u8()?;
    if magic != ETF_MAGIC {
        return Err(Error::BadEtfMagic(magic));
    }
    let next: u8 = reader.u8()?;
    if next == TAG_COMPRESSED {
        let uncompressed_size: u32 = reader.u32()?;
        let uncompressed_size_usize: usize = usize::try_from(uncompressed_size).map_err(|_| {
            Error::Zlib(
                "ETF (compressed)",
                "uncompressed size exceeds platform bounds".to_owned(),
            )
        })?;
        let rest: &[u8] = reader.take(reader.remaining())?;
        let cap: usize = uncompressed_size_usize
            .min(rest.len().saturating_mul(64))
            .min(MAX_ETF_INFLATE);
        let mut inflated: Vec<u8> = Vec::with_capacity(cap);
        let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(rest);
        let mut limited: std::io::Take<flate2::read::ZlibDecoder<&[u8]>> =
            std::io::Read::take(decoder, MAX_ETF_INFLATE as u64 + 1);
        std::io::Read::read_to_end(&mut limited, &mut inflated)
            .map_err(|e: std::io::Error| Error::Zlib("ETF (compressed)", e.to_string()))?;
        if inflated.len() > MAX_ETF_INFLATE || inflated.len() != uncompressed_size_usize {
            return Err(Error::Zlib(
                "ETF (compressed)",
                "uncompressed size mismatch".to_owned(),
            ));
        }
        let mut inner: Reader<'_> = Reader::new(&inflated);
        return decode_term(&mut inner, 0);
    }
    decode_term_after_first(&mut reader, next, 0)
}

fn decode_term(reader: &mut Reader<'_>, depth: usize) -> Result<Term> {
    let tag: u8 = reader.u8()?;
    decode_term_after_first(reader, tag, depth)
}

#[allow(clippy::too_many_lines)]
fn decode_term_after_first(reader: &mut Reader<'_>, tag: u8, depth: usize) -> Result<Term> {
    if depth > MAX_ETF_DEPTH {
        return Err(Error::DepthExceeded {
            kind: "ETF term",
            limit: MAX_ETF_DEPTH,
        });
    }
    match tag {
        TAG_SMALL_INTEGER => Ok(Term::SmallInt(reader.u8()?)),
        TAG_INTEGER => {
            let raw: u32 = reader.u32()?;
            #[allow(clippy::cast_possible_wrap)]
            Ok(Term::Int(raw as i32))
        }
        TAG_NEW_FLOAT => Ok(Term::Float(reader.f64()?)),
        TAG_FLOAT_STRING => {
            let bytes: &[u8] = reader.take(31)?;
            let trimmed: Vec<u8> = bytes.iter().copied().take_while(|&b| b != 0).collect();
            let s: &str =
                core::str::from_utf8(&trimmed).map_err(|_| Error::BadAtomUtf8 { index: 0 })?;
            let f: f64 = s
                .trim()
                .parse::<f64>()
                .map_err(|_| Error::IntOverflow("float_string"))?;
            Ok(Term::Float(f))
        }
        TAG_ATOM_UTF8 => {
            let len: u16 = reader.u16()?;
            let bytes: &[u8] = reader.take(usize::from(len))?;
            Ok(Term::Atom(decode_atom_utf8(bytes, 0)?))
        }
        TAG_SMALL_ATOM_UTF8 => {
            let len: u8 = reader.u8()?;
            let bytes: &[u8] = reader.take(usize::from(len))?;
            Ok(Term::Atom(decode_atom_utf8(bytes, 0)?))
        }
        TAG_ATOM_DEPRECATED => {
            let len: usize = usize::from(reader.u16()?);
            if len > MAX_DEPRECATED_ATOM_LATIN1_CHARS {
                return Err(Error::AtomTooLong {
                    index: 0,
                    scalars: len,
                    limit: MAX_DEPRECATED_ATOM_LATIN1_CHARS,
                });
            }
            let bytes: &[u8] = reader.take(len)?;
            let s: String = bytes.iter().map(|&b| b as char).collect();
            Ok(Term::Atom(s))
        }
        TAG_SMALL_ATOM_DEPRECATED => {
            let len: u8 = reader.u8()?;
            let bytes: &[u8] = reader.take(usize::from(len))?;
            let s: String = bytes.iter().map(|&b| b as char).collect();
            Ok(Term::Atom(s))
        }
        TAG_SMALL_TUPLE => {
            let arity: u8 = reader.u8()?;
            let arity_usize: usize = usize::from(arity);
            let cap: usize =
                bounded_container_prealloc(arity_usize, MIN_TERM_TAG_BYTES, reader.remaining());
            let mut items: Vec<Term> = Vec::with_capacity(cap);
            for _ in 0..arity {
                items.push(decode_term(reader, depth + 1)?);
            }
            Ok(Term::Tuple(items))
        }
        TAG_LARGE_TUPLE => {
            let arity: u32 = reader.u32()?;
            let arity_usize: usize = usize_from_u32(arity, "large tuple arity")?;
            let cap: usize =
                bounded_container_prealloc(arity_usize, MIN_TERM_TAG_BYTES, reader.remaining());
            let mut items: Vec<Term> = Vec::with_capacity(cap);
            for _ in 0..arity {
                items.push(decode_term(reader, depth + 1)?);
            }
            Ok(Term::Tuple(items))
        }
        TAG_NIL => Ok(Term::Nil),
        TAG_STRING => {
            let len: u16 = reader.u16()?;
            let bytes: Vec<u8> = reader.take(usize::from(len))?.to_vec();
            Ok(Term::String(bytes))
        }
        TAG_LIST => {
            let len: u32 = reader.u32()?;
            let len_usize: usize = usize_from_u32(len, "list length")?;
            let cap: usize =
                bounded_container_prealloc(len_usize, MIN_TERM_TAG_BYTES, reader.remaining());
            let mut items: Vec<Term> = Vec::with_capacity(cap);
            for _ in 0..len {
                items.push(decode_term(reader, depth + 1)?);
            }
            let tail: Term = decode_term(reader, depth + 1)?;
            Ok(Term::List {
                elements: items,
                tail: Box::new(tail),
            })
        }
        TAG_BINARY => {
            let len: u32 = reader.u32()?;
            let len_usize: usize = usize_from_u32(len, "binary length")?;
            let bytes: Vec<u8> = reader.take(len_usize)?.to_vec();
            Ok(Term::Binary(bytes))
        }
        TAG_BIT_BINARY => {
            let len: u32 = reader.u32()?;
            let bits: u8 = reader.u8()?;
            let len_usize: usize = usize_from_u32(len, "bit binary length")?;
            let bytes: Vec<u8> = reader.take(len_usize)?.to_vec();
            Ok(Term::BitBinary { bits, data: bytes })
        }
        TAG_SMALL_BIG => {
            let len: u8 = reader.u8()?;
            let sign: u8 = reader.u8()?;
            let bytes: Vec<u8> = reader.take(usize::from(len))?.to_vec();
            Ok(Term::BigInt {
                sign,
                magnitude_le: bytes,
            })
        }
        TAG_LARGE_BIG => {
            let len: u32 = reader.u32()?;
            let sign: u8 = reader.u8()?;
            let len_usize: usize = usize_from_u32(len, "large big length")?;
            let bytes: Vec<u8> = reader.take(len_usize)?.to_vec();
            Ok(Term::BigInt {
                sign,
                magnitude_le: bytes,
            })
        }
        TAG_MAP => {
            let arity: u32 = reader.u32()?;
            let arity_usize: usize = usize_from_u32(arity, "map arity")?;
            let cap: usize =
                bounded_container_prealloc(arity_usize, MIN_MAP_PAIR_BYTES, reader.remaining());
            let mut pairs: Vec<(Term, Term)> = Vec::with_capacity(cap);
            let mut all_string_keys: bool = true;
            for _ in 0..arity {
                let k: Term = decode_term(reader, depth + 1)?;
                let v: Term = decode_term(reader, depth + 1)?;
                if !matches!(&k, Term::Atom(_) | Term::Binary(_) | Term::String(_)) {
                    all_string_keys = false;
                }
                pairs.push((k, v));
            }
            if all_string_keys && string_keys_are_unique(&pairs) {
                let mut map: BTreeMap<String, Term> = BTreeMap::new();
                for (k, v) in pairs {
                    let key: String = k
                        .as_str()
                        .ok_or(Error::UnsupportedEtfTag { tag, offset: 0 })?;
                    map.insert(key, v);
                }
                Ok(Term::Map(map))
            } else {
                Ok(Term::MapMixed(pairs))
            }
        }
        TAG_NEW_PID => {
            let node: Term = decode_term(reader, depth + 1)?;
            let id: u32 = reader.u32()?;
            let serial: u32 = reader.u32()?;
            let creation: u32 = reader.u32()?;
            Ok(Term::Pid {
                node: node.as_atom().unwrap_or("").to_owned(),
                id,
                serial,
                creation,
            })
        }
        TAG_EXPORT => {
            let module_term: Term = decode_term(reader, depth + 1)?;
            let function_term: Term = decode_term(reader, depth + 1)?;
            let arity_term: Term = decode_term(reader, depth + 1)?;
            let module: String = module_term
                .as_atom()
                .ok_or(Error::UnsupportedEtfTag { tag, offset: 0 })?
                .to_owned();
            let function: String = function_term
                .as_atom()
                .ok_or(Error::UnsupportedEtfTag { tag, offset: 0 })?
                .to_owned();
            let arity: u32 = match arity_term {
                Term::SmallInt(v) => u32::from(v),
                #[allow(clippy::cast_sign_loss)]
                Term::Int(v) if v >= 0 => v as u32,
                _ => return Err(Error::UnsupportedEtfTag { tag, offset: 0 }),
            };
            Ok(Term::Export {
                module,
                function,
                arity,
            })
        }
        TAG_NEWER_REFERENCE => {
            let len: u16 = reader.u16()?;
            let node: Term = decode_term(reader, depth + 1)?;
            let creation: u32 = reader.u32()?;
            let cap: usize = bounded_container_prealloc(
                usize::from(len),
                REFERENCE_ID_BYTES,
                reader.remaining(),
            );
            let mut ids: Vec<u32> = Vec::with_capacity(cap);
            for _ in 0..len {
                ids.push(reader.u32()?);
            }
            Ok(Term::Reference {
                node: node.as_atom().unwrap_or("").to_owned(),
                creation,
                ids,
            })
        }
        other => Err(Error::UnsupportedEtfTag {
            tag: other,
            offset: reader.position(),
        }),
    }
}

fn usize_from_u32(value: u32, kind: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::IntOverflow(kind))
}

fn bounded_container_prealloc(declared: usize, min_item_bytes: usize, remaining: usize) -> usize {
    let byte_bound: usize = remaining.checked_div(min_item_bytes).unwrap_or(0);
    declared.min(byte_bound).min(MAX_ETF_CONTAINER_PREALLOC)
}

fn string_keys_are_unique(pairs: &[(Term, Term)]) -> bool {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (k, _) in pairs {
        if let Some(key) = k.as_str()
            && !seen.insert(key)
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn container_prealloc_caps_declared_count() {
        let cap: usize = bounded_container_prealloc(usize::MAX, MIN_TERM_TAG_BYTES, usize::MAX);
        assert_eq!(cap, MAX_ETF_CONTAINER_PREALLOC);

        let byte_limited: usize = bounded_container_prealloc(usize::MAX, MIN_MAP_PAIR_BYTES, 31);
        assert_eq!(byte_limited, 15);
    }

    #[test]
    fn huge_tuple_count_truncates_without_declared_capacity() {
        let mut bytes: Vec<u8> = vec![ETF_MAGIC, TAG_LARGE_TUPLE];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.push(TAG_NIL);

        let err: Error = decode_etf(&bytes).expect_err("oversized tuple must truncate");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn distinct_atom_keys_use_queryable_map() {
        let mut bytes: Vec<u8> = vec![ETF_MAGIC, TAG_MAP];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[TAG_SMALL_ATOM_UTF8, 1, b'a', TAG_SMALL_INTEGER, 1]);
        bytes.extend_from_slice(&[TAG_SMALL_ATOM_UTF8, 1, b'b', TAG_SMALL_INTEGER, 2]);
        let term: Term = decode_etf(&bytes).expect("atom-keyed map decodes");
        let map: &BTreeMap<String, Term> =
            term.as_map().expect("distinct atom keys stay queryable");
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("a"), Some(&Term::SmallInt(1)));
        assert_eq!(map.get("b"), Some(&Term::SmallInt(2)));
    }

    #[test]
    fn single_binary_key_map_stays_queryable() {
        let mut bytes: Vec<u8> = vec![ETF_MAGIC, TAG_MAP];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(TAG_BINARY);
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(b"en");
        bytes.extend_from_slice(&[TAG_SMALL_INTEGER, 7]);
        let term: Term = decode_etf(&bytes).expect("binary-keyed map decodes");
        let map: &BTreeMap<String, Term> = term
            .as_map()
            .expect("unique binary key stays queryable for docs lookup");
        assert_eq!(map.get("en"), Some(&Term::SmallInt(7)));
    }

    #[test]
    fn colliding_typed_keys_preserve_every_entry() {
        let mut bytes: Vec<u8> = vec![ETF_MAGIC, TAG_MAP];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[
            TAG_SMALL_ATOM_UTF8,
            3,
            b'f',
            b'o',
            b'o',
            TAG_SMALL_INTEGER,
            1,
        ]);
        bytes.push(TAG_BINARY);
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(b"foo");
        bytes.extend_from_slice(&[TAG_SMALL_INTEGER, 2]);
        let term: Term = decode_etf(&bytes).expect("colliding-key map decodes");
        let expected: Term = Term::MapMixed(vec![
            (Term::Atom("foo".to_owned()), Term::SmallInt(1)),
            (Term::Binary(b"foo".to_vec()), Term::SmallInt(2)),
        ]);
        assert_eq!(
            term, expected,
            "atom/binary key collision must keep both entries as MapMixed"
        );
        assert!(
            term.as_map().is_none(),
            "MapMixed is not the queryable form"
        );
    }
}
