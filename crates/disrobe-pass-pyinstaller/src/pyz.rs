use std::io::Read;

use disrobe_py_marshal::{Object, PyVersion, load, pyversion_from_magic};
use flate2::read::ZlibDecoder;
use serde::Serialize;

use crate::crypto::{AesMode, decrypt};
use crate::error::{Error, Result};

const PYZ_MAGIC: &[u8; 4] = b"PYZ\0";

const MAX_PYZ_TOC_ENTRIES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PyzTocKind {
    Module,
    Package,
    Data,
    Unknown(i32),
}

impl PyzTocKind {
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Module,
            1 => Self::Package,
            2 => Self::Data,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
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
    let mut budget: u64 = MAX_AGGREGATE_INFLATE;
    extract_pyz_bounded(pyz_bytes, &mut budget, None)
}

pub fn extract_pyz_with_key(
    pyz_bytes: &[u8],
    key: &[u8; 16],
) -> Result<(PyVersion, Vec<PyzEntry>)> {
    let mut budget: u64 = MAX_AGGREGATE_INFLATE;
    extract_pyz_bounded(pyz_bytes, &mut budget, Some(key))
}

pub(crate) fn extract_pyz_bounded(
    pyz_bytes: &[u8],
    inflate_budget: &mut u64,
    key: Option<&[u8; 16]>,
) -> Result<(PyVersion, Vec<PyzEntry>)> {
    if pyz_bytes.len() < 12 {
        return Err(Error::BadPyzMagic([0; 4]));
    }
    let magic_check: [u8; 4] = pyz_bytes[..4]
        .try_into()
        .map_err(|_| Error::BadPyzMagic([0; 4]))?;
    if &magic_check != PYZ_MAGIC {
        return Err(Error::BadPyzMagic(magic_check));
    }
    let pyc_magic: u32 =
        u32::from_le_bytes([pyz_bytes[4], pyz_bytes[5], pyz_bytes[6], pyz_bytes[7]]);
    let py_version: PyVersion =
        pyversion_from_magic(pyc_magic).ok_or(Error::UnknownPyzMagic(pyc_magic))?;
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
    let entries: Vec<PyzEntry> = walk_pyz_toc(&toc_obj, pyz_bytes, inflate_budget, key)?;
    Ok((py_version, entries))
}

fn walk_pyz_toc(
    toc_obj: &Object,
    pyz_bytes: &[u8],
    inflate_budget: &mut u64,
    key: Option<&[u8; 16]>,
) -> Result<Vec<PyzEntry>> {
    let item_count: usize = checked_toc_capacity(toc_item_count(toc_obj))?;
    let mut out: Vec<PyzEntry> = Vec::with_capacity(item_count);
    match toc_obj {
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (k, v) in d {
                if let Some(name) = string_value(k)
                    && let Object::Tuple(t) = v
                {
                    push_pyz_entry(&mut out, name, t, pyz_bytes, inflate_budget, key)?;
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
                    push_pyz_entry(&mut out, name, t, pyz_bytes, inflate_budget, key)?;
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

fn push_pyz_entry(
    out: &mut Vec<PyzEntry>,
    name: String,
    tuple: &[Object],
    pyz_bytes: &[u8],
    inflate_budget: &mut u64,
    key: Option<&[u8; 16]>,
) -> Result<()> {
    let Some((kind, position, length)): Option<(PyzTocKind, i32, i32)> =
        tuple_to_kind_pos_len(tuple)
    else {
        return Ok(());
    };
    let (Ok(pos_usize), Ok(len_usize)): (
        core::result::Result<usize, _>,
        core::result::Result<usize, _>,
    ) = (usize::try_from(position), usize::try_from(length)) else {
        return Ok(());
    };
    let Some(end): Option<usize> = pos_usize.checked_add(len_usize) else {
        return Ok(());
    };
    if len_usize == 0 || end > pyz_bytes.len() {
        return Ok(());
    }
    let raw: &[u8] = &pyz_bytes[pos_usize..end];
    let decompressed: Vec<u8> = match decode_pyz_payload(raw, key, inflate_budget) {
        Some(body) => body,
        None => {
            return Err(Error::Inflate {
                name,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "pyz entry is neither plain zlib nor decryptable with the recovered key",
                ),
            });
        }
    };
    out.push(PyzEntry {
        name,
        kind,
        position,
        length,
        bytes: decompressed,
    });
    Ok(())
}

fn decode_pyz_payload(
    raw: &[u8],
    key: Option<&[u8; 16]>,
    inflate_budget: &mut u64,
) -> Option<Vec<u8>> {
    if let Ok(body) = inflate(raw, inflate_budget) {
        return Some(body);
    }
    let key: &[u8; 16] = key?;
    for mode in [AesMode::Ctr, AesMode::Cfb8] {
        let Some(plain): Option<Vec<u8>> = decrypt(raw, key, mode) else {
            continue;
        };
        if let Ok(body) = inflate(&plain, inflate_budget) {
            return Some(body);
        }
    }
    None
}

fn toc_item_count(obj: &Object) -> usize {
    match obj {
        Object::Dict(items) | Object::FrozenDict(items) => items.len(),
        Object::List(items) | Object::Tuple(items) => items.len(),
        _ => 0,
    }
}

fn checked_toc_capacity(count: usize) -> Result<usize> {
    if count > MAX_PYZ_TOC_ENTRIES {
        return Err(Error::TocWalk(
            0,
            format!("pyz toc declares {count} entries, exceeding {MAX_PYZ_TOC_ENTRIES}"),
        ));
    }
    Ok(count)
}

fn string_value(obj: &Object) -> Option<String> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
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

const MAX_INFLATE_RATIO: u64 = 1024;
const MAX_INFLATE_ABS: u64 = 4 * 1024 * 1024 * 1024;
const MAX_AGGREGATE_INFLATE: u64 = 8 * 1024 * 1024 * 1024;

fn inflate(input: &[u8], aggregate_budget: &mut u64) -> std::io::Result<Vec<u8>> {
    let cap: u64 = (input.len() as u64)
        .saturating_mul(MAX_INFLATE_RATIO)
        .min(MAX_INFLATE_ABS)
        .min(*aggregate_budget);
    let budget: u64 = cap.saturating_add(1);
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    let mut limited: std::io::Take<ZlibDecoder<&[u8]>> = decoder.take(budget);
    let mut out: Vec<u8> = Vec::new();
    limited.read_to_end(&mut out)?;
    if out.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decompressed pyz entry exceeds bomb cap of {cap} bytes"),
        ));
    }
    *aggregate_budget = aggregate_budget.saturating_sub(out.len() as u64);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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
    fn inflate_roundtrips_small_payload() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let payload: &[u8] = b"hello pyz module body";
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        let mut budget: u64 = MAX_AGGREGATE_INFLATE;
        let out: Vec<u8> = inflate(&compressed, &mut budget).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn inflate_rejects_decompression_bomb() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let zeros: Vec<u8> = vec![0u8; 64 * 1024 * 1024];
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&zeros).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        assert!(
            (compressed.len() as u64) * MAX_INFLATE_RATIO < zeros.len() as u64,
            "test bomb must exceed the ratio cap to be meaningful"
        );
        let mut budget: u64 = MAX_AGGREGATE_INFLATE;
        let err: std::io::Error = inflate(&compressed, &mut budget).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn inflate_surfaces_error_instead_of_substituting_raw() {
        let not_zlib: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut budget: u64 = MAX_AGGREGATE_INFLATE;
        assert!(
            inflate(&not_zlib, &mut budget).is_err(),
            "corrupt stream must error, never silently pass through the compressed bytes"
        );
    }

    #[test]
    fn rejects_negative_toc_offset() {
        use disrobe_py_marshal::magic_for;
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..4].copy_from_slice(PYZ_MAGIC);
        let py312_magic: u32 = magic_for(PyVersion::PY312).expect("3.12 has a known pyc magic");
        bytes[4..8].copy_from_slice(&py312_magic.to_le_bytes());
        bytes[8..12].copy_from_slice(&(-1i32).to_be_bytes());
        let err: Option<Error> = extract_pyz(&bytes).err();
        assert!(matches!(err, Some(Error::TocWalk(_, _))));
    }

    #[test]
    fn unknown_pyc_magic_errors_instead_of_defaulting() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..4].copy_from_slice(PYZ_MAGIC);
        let bogus: u32 = 0x0000_3495;
        bytes[4..8].copy_from_slice(&bogus.to_le_bytes());
        bytes[8..12].copy_from_slice(&16i32.to_be_bytes());
        let err: Option<Error> = extract_pyz(&bytes).err();
        assert!(
            matches!(err, Some(Error::UnknownPyzMagic(m)) if m == bogus),
            "an unrecognised pyc magic must surface explicitly, never silently assume 3.12",
        );
    }

    #[test]
    fn pyz_toc_capacity_rejects_over_cap() {
        let err: Error = checked_toc_capacity(MAX_PYZ_TOC_ENTRIES + 1)
            .expect_err("oversized pyz toc must fail before allocation");
        assert!(matches!(err, Error::TocWalk(_, _)));
    }

    fn build_pyz(toc: &Object, body: &[u8], py_version: PyVersion) -> Vec<u8> {
        use disrobe_py_marshal::{dump, magic_for};
        let marshalled_toc: Vec<u8> = dump(toc, py_version).expect("marshal pyz toc");
        let header_len: usize = 12;
        let toc_pos: i32 = i32::try_from(header_len + body.len()).expect("toc offset fits i32");
        let mut out: Vec<u8> = Vec::with_capacity(header_len + body.len() + marshalled_toc.len());
        let pyc_magic: u32 = magic_for(py_version).expect("py version has a known pyc magic");
        out.extend_from_slice(PYZ_MAGIC);
        out.extend_from_slice(&pyc_magic.to_le_bytes());
        out.extend_from_slice(&toc_pos.to_be_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&marshalled_toc);
        out
    }

    fn zlib_compress(payload: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload)
            .expect("zlib compress pyz module body");
        enc.finish().expect("zlib finish")
    }

    #[test]
    fn recovers_unicode_named_module_entry() {
        use indexmap::IndexMap;
        let module_body: &[u8] = b"# coding: utf-8\nvalue = 'caf\xc3\xa9'\n";
        let compressed: Vec<u8> = zlib_compress(module_body);
        let position: i32 = 12;
        let length: i32 = i32::try_from(compressed.len()).expect("entry length fits i32");
        let mut toc_map: IndexMap<Object, Object> = IndexMap::new();
        toc_map.insert(
            Object::Unicode {
                value: "pakket_café".to_owned(),
                interned: false,
            },
            Object::Tuple(vec![
                Object::Int(0),
                Object::Int(position),
                Object::Int(length),
            ]),
        );
        let toc: Object = Object::Dict(toc_map);
        let pyz: Vec<u8> = build_pyz(&toc, &compressed, PyVersion::PY312);

        let (_, entries): (PyVersion, Vec<PyzEntry>) =
            extract_pyz(&pyz).expect("pyz with unicode-named module must extract");
        assert_eq!(
            entries.len(),
            1,
            "unicode-tagged module name must not be dropped from the pyz toc",
        );
        assert_eq!(
            entries[0].name, "pakket_café",
            "the u-tagged module name must surface verbatim",
        );
        assert_eq!(entries[0].kind, PyzTocKind::Module);
        assert_eq!(
            entries[0].bytes, module_body,
            "the decompressed module body must round-trip",
        );
    }

    #[test]
    fn unicode_module_name_dropped_without_unicode_arm() {
        let toc: Object = Object::Tuple(vec![Object::Tuple(vec![
            Object::Unicode {
                value: "naïve".to_owned(),
                interned: false,
            },
            Object::Tuple(vec![Object::Int(0), Object::Int(12), Object::Int(0)]),
        ])]);
        let pyz: Vec<u8> = build_pyz(&toc, &[], PyVersion::PY312);
        let (_, entries): (PyVersion, Vec<PyzEntry>) =
            extract_pyz(&pyz).expect("zero-length entry path must still parse the toc");
        assert!(
            entries.is_empty(),
            "a zero-length entry is skipped, but the unicode name itself must have been recognised",
        );
        assert_eq!(
            string_value(&Object::Unicode {
                value: "naïve".to_owned(),
                interned: false,
            }),
            Some("naïve".to_owned()),
            "string_value must accept a u-tagged unicode name",
        );
    }
}
