use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::etf::{self, Term};

const DBGI_METADATA_INFLATE_MAX: usize = 16 * 1024 * 1024;
const DBGI_METADATA_INFLATE_MAX_U64: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DebugInfo {
    ElixirV1 { backend: String, metadata: Term },
    ErlangAbstractCode { forms: Term, compile_opts: Term },
    Other(Term),
}

pub fn parse(term: &Term) -> Result<DebugInfo> {
    let tuple: &[Term] = term
        .as_tuple()
        .ok_or_else(|| Error::NotElixirDbgi("not a tuple".to_owned()))?;
    if tuple.len() == 3
        && let Some(tag) = tuple[0].as_atom()
        && tag == "debug_info_v1"
    {
        let backend: String = tuple[1]
            .as_atom()
            .ok_or_else(|| Error::NotElixirDbgi("missing backend atom".to_owned()))?
            .to_owned();
        if backend == "erl_abstract_code" {
            return Ok(parse_erl_abstract_code(&tuple[2]));
        }
        let metadata: Term = decode_metadata(&tuple[2])?;
        return Ok(DebugInfo::ElixirV1 { backend, metadata });
    }
    if tuple.len() == 2
        && let Some(tag) = tuple[0].as_atom()
        && (tag == "raw_abstract_v1" || tag == "abstract_code")
    {
        let forms_pair: &Term = &tuple[1];
        if let Some(inner) = forms_pair.as_tuple()
            && inner.len() == 2
        {
            return Ok(DebugInfo::ErlangAbstractCode {
                forms: inner[1].clone(),
                compile_opts: Term::Nil,
            });
        }
        return Ok(DebugInfo::ErlangAbstractCode {
            forms: forms_pair.clone(),
            compile_opts: Term::Nil,
        });
    }
    Ok(DebugInfo::Other(term.clone()))
}

fn parse_erl_abstract_code(payload: &Term) -> DebugInfo {
    if let Some(inner) = payload.as_tuple()
        && inner.len() == 2
    {
        return DebugInfo::ErlangAbstractCode {
            forms: inner[0].clone(),
            compile_opts: inner[1].clone(),
        };
    }
    DebugInfo::ErlangAbstractCode {
        forms: payload.clone(),
        compile_opts: Term::Nil,
    }
}

fn decode_metadata(term: &Term) -> Result<Term> {
    match term {
        Term::Binary(bytes) => {
            if let Some(t) = decode_zlib_metadata(bytes)? {
                return Ok(t);
            }
            if !bytes.is_empty()
                && bytes[0] == etf::ETF_MAGIC
                && let Ok(t) = etf::decode_etf(bytes)
            {
                return Ok(t);
            }
            Ok(Term::Binary(bytes.clone()))
        }
        other => Ok(other.clone()),
    }
}

fn decode_zlib_metadata(bytes: &[u8]) -> Result<Option<Term>> {
    let cap: usize = bytes.len().saturating_mul(2).min(DBGI_METADATA_INFLATE_MAX);
    let mut decoded: Vec<u8> = Vec::with_capacity(cap);
    let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(bytes);
    let mut limited: std::io::Take<flate2::read::ZlibDecoder<&[u8]>> =
        decoder.take(DBGI_METADATA_INFLATE_MAX_U64.saturating_add(1));
    match limited.read_to_end(&mut decoded) {
        Ok(_) => {
            if decoded.is_empty() {
                return Ok(None);
            }
            if decoded.len() > DBGI_METADATA_INFLATE_MAX {
                return Err(Error::Zlib(
                    "Dbgi",
                    "metadata inflate ceiling exceeded".to_owned(),
                ));
            }
            etf::decode_etf(&decoded).map(Some)
        }
        Err(err) => {
            if looks_like_zlib(bytes) {
                Err(Error::Zlib("Dbgi", err.to_string()))
            } else {
                Ok(None)
            }
        }
    }
}

fn looks_like_zlib(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let cmf: u8 = bytes[0];
    let flg: u8 = bytes[1];
    let method_is_deflate: bool = cmf & 0x0f == 8;
    let window_valid: bool = cmf >> 4 <= 7;
    let header: u16 = (u16::from(cmf) << 8) | u16::from(flg);
    method_is_deflate && window_valid && header.is_multiple_of(31)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use super::*;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder: ZlibEncoder<Vec<u8>> =
            ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("zlib write");
        encoder.finish().expect("zlib finish")
    }

    #[test]
    fn dbgi_metadata_zlib_bomb_errors() {
        let payload: Vec<u8> = vec![0u8; DBGI_METADATA_INFLATE_MAX + 1];
        let term: Term = Term::Tuple(vec![
            Term::Atom("debug_info_v1".to_owned()),
            Term::Atom("elixir_erl".to_owned()),
            Term::Binary(zlib_compress(&payload)),
        ]);
        let err: Error = parse(&term).expect_err("oversized Dbgi metadata must fail");
        assert!(matches!(err, Error::Zlib("Dbgi", _)));
    }
}
