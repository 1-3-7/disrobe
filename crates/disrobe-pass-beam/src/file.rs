use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::chunks::{
    self, AtomTable, AttrChunk, Chunks, CodeChunk, CompileInfoChunk, DbgiChunk, DocsChunk,
    LiteralChunk, StringTable,
};
use crate::debug::{dbg_enabled, dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};
use crate::etf;
use crate::reader::Reader;

pub const IFF_MAGIC: [u8; 4] = *b"FOR1";
pub const FORM_TYPE: [u8; 4] = *b"BEAM";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawChunk {
    pub tag: [u8; 4],
    pub offset: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawBeam {
    pub form_length: u32,
    pub raw_chunks: Vec<RawChunk>,
}

impl RawBeam {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(buf);
        let magic: [u8; 4] = reader.tag()?;
        if magic != IFF_MAGIC {
            return Err(Error::BadIffMagic(magic));
        }
        let form_length: u32 = reader.u32()?;
        let form_length_usize: usize =
            usize::try_from(form_length).map_err(|_| Error::BadFormLength {
                declared: usize::MAX,
                available: reader.remaining(),
            })?;
        if form_length_usize > reader.remaining() {
            return Err(Error::BadFormLength {
                declared: form_length_usize,
                available: reader.remaining(),
            });
        }
        let form_type: [u8; 4] = reader.tag()?;
        if form_type != FORM_TYPE {
            return Err(Error::BadFormType(form_type));
        }
        dbg_section("iff chunk parse");
        dbg_kv("form_length", || form_length.to_string());
        let end: usize = 8usize
            .checked_add(form_length_usize)
            .ok_or(Error::BadFormLength {
                declared: form_length_usize,
                available: reader.remaining(),
            })?;
        let mut raw_chunks: Vec<RawChunk> = Vec::new();
        while reader.position() < end {
            let chunk_start: usize = reader.position();
            let tag: [u8; 4] = reader.tag()?;
            let len: u32 = reader.u32()?;
            let len_usize: usize = usize::try_from(len).map_err(|_| Error::BadChunkLength {
                tag: ascii_tag(&tag),
                len: usize::MAX,
                remaining: end.saturating_sub(reader.position()),
            })?;
            if dbg_enabled() {
                dbg_line(|| format!("chunk {} offset={chunk_start} len={len}", ascii_tag(&tag)));
            }
            let remaining_in_form: usize =
                end.checked_sub(reader.position())
                    .ok_or_else(|| Error::BadChunkLength {
                        tag: ascii_tag(&tag),
                        len: len_usize,
                        remaining: 0,
                    })?;
            if len_usize > remaining_in_form {
                return Err(Error::BadChunkLength {
                    tag: ascii_tag(&tag),
                    len: len_usize,
                    remaining: remaining_in_form,
                });
            }
            let data: Vec<u8> = reader.take(len_usize)?.to_vec();
            let padding: usize = (4 - (len_usize % 4)) % 4;
            if padding != 0 {
                let remaining_padding: usize =
                    end.checked_sub(reader.position())
                        .ok_or_else(|| Error::BadChunkLength {
                            tag: ascii_tag(&tag),
                            len: padding,
                            remaining: 0,
                        })?;
                if padding > remaining_padding {
                    return Err(Error::BadChunkLength {
                        tag: ascii_tag(&tag),
                        len: len_usize.saturating_add(padding),
                        remaining: remaining_padding,
                    });
                }
                reader.take(padding)?;
            }
            raw_chunks.push(RawChunk {
                tag,
                offset: chunk_start,
                data,
            });
        }
        Ok(Self {
            form_length,
            raw_chunks,
        })
    }

    #[must_use]
    pub fn find(&self, tag: &[u8; 4]) -> Option<&RawChunk> {
        self.raw_chunks.iter().find(|c: &&RawChunk| &c.tag == tag)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeamFile {
    pub form_length: u32,
    pub chunks: Chunks,
}

impl BeamFile {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let raw: RawBeam = RawBeam::parse(buf)?;
        Self::from_raw(&raw)
    }

    pub fn from_raw(raw: &RawBeam) -> Result<Self> {
        let atoms: AtomTable = if let Some(c) = raw.find(b"AtU8") {
            dbg_kv("atom_chunk", || format!("AtU8 (utf8) len={}", c.data.len()));
            AtomTable::parse_utf8_any(&c.data)?
        } else if let Some(c) = raw.find(b"Atom") {
            dbg_kv("atom_chunk", || {
                format!("Atom (latin1) len={}", c.data.len())
            });
            AtomTable::parse_latin1(&c.data)?
        } else {
            dbg_line(|| "no Atom/AtU8 chunk: not a BEAM module".to_owned());
            return Err(Error::MissingChunk("Atom/AtU8"));
        };

        let code: Option<CodeChunk> = raw
            .find(b"Code")
            .map(|c: &RawChunk| CodeChunk::parse(&c.data))
            .transpose()?;
        let strings: Option<StringTable> = raw
            .find(b"StrT")
            .map(|c: &RawChunk| StringTable::parse(&c.data));
        let exports: Vec<chunks::ExportEntry> = raw
            .find(b"ExpT")
            .map(|c: &RawChunk| chunks::parse_export_table(&c.data))
            .transpose()?
            .unwrap_or_default();
        let imports: Vec<chunks::ImportEntry> = raw
            .find(b"ImpT")
            .map(|c: &RawChunk| chunks::parse_import_table(&c.data))
            .transpose()?
            .unwrap_or_default();
        let locals: Vec<chunks::LocalEntry> = raw
            .find(b"LocT")
            .map(|c: &RawChunk| chunks::parse_local_table(&c.data))
            .transpose()?
            .unwrap_or_default();
        let attributes: Option<AttrChunk> = raw
            .find(b"Attr")
            .map(|c: &RawChunk| etf::decode_etf(&c.data).map(|t: etf::Term| AttrChunk { term: t }))
            .transpose()?;
        let compile_info: Option<CompileInfoChunk> = raw
            .find(b"CInf")
            .map(|c: &RawChunk| {
                etf::decode_etf(&c.data).map(|t: etf::Term| CompileInfoChunk { term: t })
            })
            .transpose()?;
        let dbgi: Option<DbgiChunk> = raw
            .find(b"Dbgi")
            .map(|c: &RawChunk| etf::decode_etf(&c.data).map(|t: etf::Term| DbgiChunk { term: t }))
            .transpose()?;
        let docs: Option<DocsChunk> = raw
            .find(b"Docs")
            .map(|c: &RawChunk| etf::decode_etf(&c.data).map(|t: etf::Term| DocsChunk { term: t }))
            .transpose()?;
        let literals: Option<LiteralChunk> = raw
            .find(b"LitT")
            .map(|c: &RawChunk| LiteralChunk::parse(&c.data))
            .transpose()?;
        let line: Option<chunks::LineChunk> = raw
            .find(b"Line")
            .or_else(|| raw.find(b"LinE"))
            .map(|c: &RawChunk| chunks::LineChunk::parse(&c.data))
            .transpose()?;
        let funs: Vec<chunks::FunEntry> = raw
            .find(b"FunT")
            .map(|c: &RawChunk| chunks::parse_fun_table(&c.data))
            .transpose()?
            .unwrap_or_default();

        let known: &[&[u8; 4]] = &[
            b"AtU8", b"Atom", b"Code", b"StrT", b"ExpT", b"ImpT", b"LocT", b"Attr", b"CInf",
            b"Dbgi", b"Docs", b"LitT", b"Line", b"LinE", b"FunT",
        ];
        let mut other: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for c in &raw.raw_chunks {
            if !known.iter().any(|k: &&[u8; 4]| **k == c.tag) {
                other.insert(ascii_tag(&c.tag), c.data.clone());
            }
        }

        Ok(Self {
            form_length: raw.form_length,
            chunks: Chunks {
                atoms,
                code,
                strings,
                attributes,
                compile_info,
                dbgi,
                docs,
                exports,
                imports,
                locals,
                literals,
                line,
                funs,
                other,
            },
        })
    }

    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.chunks.atoms.module_name()
    }
}

fn ascii_tag(tag: &[u8; 4]) -> String {
    tag.iter()
        .map(|&b: &u8| if b.is_ascii_graphic() { b as char } else { '.' })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn raw_beam_with_chunk(data: &[u8], include_padding: bool) -> Vec<u8> {
        let padding: usize = if include_padding {
            (4 - (data.len() % 4)) % 4
        } else {
            0
        };
        let form_length: u32 =
            u32::try_from(4 + 8 + data.len() + padding).expect("test beam size fits u32");
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&IFF_MAGIC);
        bytes.extend_from_slice(&form_length.to_be_bytes());
        bytes.extend_from_slice(&FORM_TYPE);
        bytes.extend_from_slice(b"Tst0");
        bytes.extend_from_slice(
            &u32::try_from(data.len())
                .expect("test chunk len")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(data);
        bytes.extend(std::iter::repeat_n(0, padding));
        bytes
    }

    #[test]
    fn raw_beam_rejects_missing_chunk_padding() {
        let bytes: Vec<u8> = raw_beam_with_chunk(b"x", false);
        let err: Error = RawBeam::parse(&bytes).expect_err("missing chunk padding must fail");
        assert!(matches!(err, Error::BadChunkLength { .. }));
    }

    #[test]
    fn raw_beam_accepts_declared_chunk_padding() {
        let bytes: Vec<u8> = raw_beam_with_chunk(b"x", true);
        let raw: RawBeam = RawBeam::parse(&bytes).expect("padded chunk parses");
        assert_eq!(raw.raw_chunks.len(), 1);
        assert_eq!(raw.raw_chunks[0].data, b"x");
    }
}
