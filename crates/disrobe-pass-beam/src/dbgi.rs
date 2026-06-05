use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::etf::{self, Term};

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

/// Decodes the `erl_abstract_code` backend payload `{Forms, CompileOpts}`.
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
            let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
            let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
                flate2::read::ZlibDecoder::new(bytes.as_slice());
            if decoder.read_to_end(&mut decoded).is_ok()
                && !decoded.is_empty()
                && let Ok(t) = etf::decode_etf(&decoded)
            {
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
