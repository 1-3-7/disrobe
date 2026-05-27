use std::io::Read;

use disrobe_py_marshal::{Object, PyVersion, load, pyversion_from_magic};
use flate2::read::ZlibDecoder;
use serde::Serialize;

use crate::error::{Error, Result};

const PYZ_MAGIC: &[u8; 4] = b"PYZ\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PyzTocKind {
    Module,
    Package,
    Data,
    Unknown(i32),
}

impl PyzTocKind {
    pub const fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Module,
            1 => Self::Package,
            2 => Self::Data,
            other => Self::Unknown(other),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Package => "package",
            Self::Data => "data",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PyzEntry {
    pub name: String,
    pub kind: PyzTocKind,
    pub position: i32,
    pub length: i32,
    pub bytes: Vec<u8>,
}

pub fn extract_pyz(pyz_bytes: &[u8]) -> Result<(PyVersion, Vec<PyzEntry>)> {
    if pyz_bytes.len() < 12 {
        return Err(Error::BadPyzMagic([0; 4]));
    }
    let magic_check: [u8; 4] = pyz_bytes[..4]
        .try_into()
        .map_err(|_| Error::BadPyzMagic([0; 4]))?;
    if &magic_check != PYZ_MAGIC {
        return Err(Error::BadPyzMagic(magic_check));
    }
    let pyc_magic: u16 = u16::from_le_bytes([pyz_bytes[4], pyz_bytes[5]]);
    let py_version: PyVersion = pyversion_from_magic(pyc_magic).unwrap_or(PyVersion::PY312);
    let toc_pos_signed: i32 =
        i32::from_be_bytes([pyz_bytes[8], pyz_bytes[9], pyz_bytes[10], pyz_bytes[11]]);
    let toc_pos: usize = usize::try_from(toc_pos_signed)
        .map_err(|_| Error::TocWalk(0, format!("negative pyz toc offset {toc_pos_signed}")))?;

    if toc_pos > pyz_bytes.len() {
        return Err(Error::TocWalk(
            toc_pos,
            "pyz toc offset exceeds blob".to_owned(),
        ));
    }

    let toc_stream: &[u8] = &pyz_bytes[toc_pos..];
    let toc_obj: Object = load(toc_stream, py_version)?;
    let entries: Vec<PyzEntry> = walk_pyz_toc(&toc_obj, pyz_bytes);
    Ok((py_version, entries))
}

fn walk_pyz_toc(toc_obj: &Object, pyz_bytes: &[u8]) -> Vec<PyzEntry> {
    let pairs: Vec<(String, Vec<Object>)> = collect_pairs(toc_obj);
    let mut out: Vec<PyzEntry> = Vec::with_capacity(pairs.len());
    for (name, tuple) in pairs {
        let Some((kind, position, length)): Option<(PyzTocKind, i32, i32)> =
            tuple_to_kind_pos_len(&tuple)
        else {
            continue;
        };
        let (Ok(pos_usize), Ok(len_usize)): (
            core::result::Result<usize, _>,
            core::result::Result<usize, _>,
        ) = (usize::try_from(position), usize::try_from(length)) else {
            continue;
        };
        if len_usize == 0 || pos_usize.saturating_add(len_usize) > pyz_bytes.len() {
            continue;
        }
        let raw: &[u8] = &pyz_bytes[pos_usize..pos_usize + len_usize];
        let decompressed: Vec<u8> = inflate(raw).unwrap_or_else(|_| raw.to_vec());
        out.push(PyzEntry {
            name,
            kind,
            position,
            length,
            bytes: decompressed,
        });
    }
    out
}

fn collect_pairs(obj: &Object) -> Vec<(String, Vec<Object>)> {
    let mut pairs: Vec<(String, Vec<Object>)> = Vec::new();
    match obj {
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (k, v) in d {
                if let Some(name) = string_value(k)
                    && let Object::Tuple(t) = v
                {
                    pairs.push((name, t.clone()));
                }
            }
        }
        Object::List(items) | Object::Tuple(items) => {
            for it in items {
                let Object::Tuple(pair) = it else { continue };
                if pair.len() != 2 {
                    continue;
                }
                let Some(name) = string_value(&pair[0]) else {
                    continue;
                };
                if let Object::Tuple(t) = &pair[1] {
                    pairs.push((name, t.clone()));
                }
            }
        }
        _ => {}
    }
    pairs
}

fn string_value(obj: &Object) -> Option<String> {
    match obj {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
        Object::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    }
}

fn tuple_to_kind_pos_len(tuple: &[Object]) -> Option<(PyzTocKind, i32, i32)> {
    if tuple.len() < 3 {
        return None;
    }
    let Object::Int(kind_i32) = &tuple[0] else {
        return None;
    };
    let Object::Int(pos) = &tuple[1] else {
        return None;
    };
    let Object::Int(len) = &tuple[2] else {
        return None;
    };
    Some((PyzTocKind::from_i32(*kind_i32), *pos, *len))
}

fn inflate(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        let bytes: Vec<u8> = vec![0u8; 32];
        let err: Option<Error> = extract_pyz(&bytes).err();
        assert!(matches!(err, Some(Error::BadPyzMagic(_))));
    }

    #[test]
    fn kind_table() {
        assert_eq!(PyzTocKind::from_i32(0), PyzTocKind::Module);
        assert_eq!(PyzTocKind::from_i32(1), PyzTocKind::Package);
        assert_eq!(PyzTocKind::from_i32(2), PyzTocKind::Data);
        assert_eq!(PyzTocKind::from_i32(99), PyzTocKind::Unknown(99));
    }

    #[test]
    fn kind_label_ascii_nonempty() {
        for k in [
            PyzTocKind::Module,
            PyzTocKind::Package,
            PyzTocKind::Data,
            PyzTocKind::Unknown(7),
        ] {
            let l: &'static str = k.label();
            assert!(l.is_ascii());
            assert!(!l.is_empty());
        }
    }

    #[test]
    fn rejects_negative_toc_offset() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..4].copy_from_slice(PYZ_MAGIC);
        bytes[4..6].copy_from_slice(&3495u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&(-1i32).to_be_bytes());
        let err: Option<Error> = extract_pyz(&bytes).err();
        assert!(matches!(err, Some(Error::TocWalk(_, _))));
    }
}
