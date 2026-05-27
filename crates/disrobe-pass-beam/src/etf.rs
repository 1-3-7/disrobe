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
        let rest: &[u8] = reader.take(reader.remaining())?;
        let mut inflated: Vec<u8> = Vec::with_capacity(uncompressed_size as usize);
        let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(rest);
        std::io::Read::read_to_end(&mut decoder, &mut inflated)
            .map_err(|e: std::io::Error| Error::Zlib("ETF (compressed)", e.to_string()))?;
        if inflated.len() != uncompressed_size as usize {
            return Err(Error::Zlib(
                "ETF (compressed)",
                "uncompressed size mismatch".to_owned(),
            ));
        }
        let mut inner: Reader<'_> = Reader::new(&inflated);
        return decode_term(&mut inner);
    }
    decode_term_after_first(&mut reader, next)
}

fn decode_term(reader: &mut Reader<'_>) -> Result<Term> {
    let tag: u8 = reader.u8()?;
    decode_term_after_first(reader, tag)
}

#[allow(clippy::too_many_lines)]
fn decode_term_after_first(reader: &mut Reader<'_>, tag: u8) -> Result<Term> {
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
            let bytes: &[u8] = reader.take(len as usize)?;
            let s: String = core::str::from_utf8(bytes)
                .map_err(|_| Error::BadAtomUtf8 { index: 0 })?
                .to_owned();
            Ok(Term::Atom(s))
        }
        TAG_SMALL_ATOM_UTF8 => {
            let len: u8 = reader.u8()?;
            let bytes: &[u8] = reader.take(len as usize)?;
            let s: String = core::str::from_utf8(bytes)
                .map_err(|_| Error::BadAtomUtf8 { index: 0 })?
                .to_owned();
            Ok(Term::Atom(s))
        }
        TAG_ATOM_DEPRECATED => {
            let len: u16 = reader.u16()?;
            let bytes: &[u8] = reader.take(len as usize)?;
            let s: String = bytes.iter().map(|&b| b as char).collect();
            Ok(Term::Atom(s))
        }
        TAG_SMALL_ATOM_DEPRECATED => {
            let len: u8 = reader.u8()?;
            let bytes: &[u8] = reader.take(len as usize)?;
            let s: String = bytes.iter().map(|&b| b as char).collect();
            Ok(Term::Atom(s))
        }
        TAG_SMALL_TUPLE => {
            let arity: u8 = reader.u8()?;
            let mut items: Vec<Term> = Vec::with_capacity(arity as usize);
            for _ in 0..arity {
                items.push(decode_term(reader)?);
            }
            Ok(Term::Tuple(items))
        }
        TAG_LARGE_TUPLE => {
            let arity: u32 = reader.u32()?;
            let cap: usize = (arity as usize).min(reader.remaining());
            let mut items: Vec<Term> = Vec::with_capacity(cap);
            for _ in 0..arity {
                items.push(decode_term(reader)?);
            }
            Ok(Term::Tuple(items))
        }
        TAG_NIL => Ok(Term::Nil),
        TAG_STRING => {
            let len: u16 = reader.u16()?;
            let bytes: Vec<u8> = reader.take(len as usize)?.to_vec();
            Ok(Term::String(bytes))
        }
        TAG_LIST => {
            let len: u32 = reader.u32()?;
            let cap: usize = (len as usize).min(reader.remaining());
            let mut items: Vec<Term> = Vec::with_capacity(cap);
            for _ in 0..len {
                items.push(decode_term(reader)?);
            }
            let tail: Term = decode_term(reader)?;
            Ok(Term::List {
                elements: items,
                tail: Box::new(tail),
            })
        }
        TAG_BINARY => {
            let len: u32 = reader.u32()?;
            let bytes: Vec<u8> = reader.take(len as usize)?.to_vec();
            Ok(Term::Binary(bytes))
        }
        TAG_BIT_BINARY => {
            let len: u32 = reader.u32()?;
            let bits: u8 = reader.u8()?;
            let bytes: Vec<u8> = reader.take(len as usize)?.to_vec();
            Ok(Term::BitBinary { bits, data: bytes })
        }
        TAG_SMALL_BIG => {
            let len: u8 = reader.u8()?;
            let sign: u8 = reader.u8()?;
            let bytes: Vec<u8> = reader.take(len as usize)?.to_vec();
            Ok(Term::BigInt {
                sign,
                magnitude_le: bytes,
            })
        }
        TAG_LARGE_BIG => {
            let len: u32 = reader.u32()?;
            let sign: u8 = reader.u8()?;
            let bytes: Vec<u8> = reader.take(len as usize)?.to_vec();
            Ok(Term::BigInt {
                sign,
                magnitude_le: bytes,
            })
        }
        TAG_MAP => {
            let arity: u32 = reader.u32()?;
            let cap: usize = (arity as usize).min(reader.remaining());
            let mut pairs: Vec<(Term, Term)> = Vec::with_capacity(cap);
            let mut all_string_keys: bool = true;
            for _ in 0..arity {
                let k: Term = decode_term(reader)?;
                let v: Term = decode_term(reader)?;
                if !matches!(&k, Term::Atom(_) | Term::Binary(_) | Term::String(_)) {
                    all_string_keys = false;
                }
                pairs.push((k, v));
            }
            if all_string_keys {
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
            let node: Term = decode_term(reader)?;
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
            let module_term: Term = decode_term(reader)?;
            let function_term: Term = decode_term(reader)?;
            let arity_term: Term = decode_term(reader)?;
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
            let node: Term = decode_term(reader)?;
            let creation: u32 = reader.u32()?;
            let mut ids: Vec<u32> = Vec::with_capacity(len as usize);
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
