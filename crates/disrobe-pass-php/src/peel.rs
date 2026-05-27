use crate::error::{Error, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use flate2::read::DeflateDecoder;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::OnceLock;

pub const DEFAULT_MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PeelLayer {
    Base64Decode,
    GzInflate,
    GzUncompress,
    StrRot13,
    StrReplace,
    EvalUnwrap,
    Fopo,
    BetterPhpObfuscator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeelTrace {
    pub layer: PeelLayer,
    pub before_len: usize,
    pub after_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeelReport {
    pub final_source: Vec<u8>,
    pub layers: Vec<PeelTrace>,
    pub layer_counts: BTreeMap<PeelLayer, u32>,
    pub residual_eval: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeelOptions {
    pub max_depth: u32,
    pub stop_when_clean: bool,
}

impl Default for PeelOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            stop_when_clean: true,
        }
    }
}

pub fn peel(source: &[u8], options: PeelOptions) -> Result<PeelReport> {
    let mut layers: Vec<PeelTrace> = Vec::new();
    let mut counts: BTreeMap<PeelLayer, u32> = BTreeMap::new();
    let mut current: Vec<u8> = source.to_vec();
    let mut depth: u32 = 0;

    loop {
        if depth >= options.max_depth {
            return Err(Error::EvalChainDepthExceeded { depth });
        }
        let before_len: usize = current.len();
        let Some((layer, next)): Option<(PeelLayer, Vec<u8>)> = try_one_layer(&current, depth)?
        else {
            if options.stop_when_clean && depth > 0 {
                break;
            }
            if depth == 0 {
                return Err(Error::EvalChainStuck { depth });
            }
            break;
        };
        layers.push(PeelTrace {
            layer,
            before_len,
            after_len: next.len(),
        });
        *counts.entry(layer).or_insert(0) += 1;
        current = next;
        depth += 1;
    }

    let residual_eval: bool = contains_eval_call(&current);
    Ok(PeelReport {
        final_source: current,
        layers,
        layer_counts: counts,
        residual_eval,
    })
}

fn try_one_layer(buf: &[u8], depth: u32) -> Result<Option<(PeelLayer, Vec<u8>)>> {
    if let Some(payload) = peel_fopo(buf, depth)? {
        return Ok(Some((PeelLayer::Fopo, payload)));
    }
    if let Some(payload) = peel_better_php(buf, depth)? {
        return Ok(Some((PeelLayer::BetterPhpObfuscator, payload)));
    }
    if let Some(payload) = peel_eval_chain(buf, depth)? {
        return Ok(Some(payload));
    }
    Ok(None)
}

fn peel_eval_chain(buf: &[u8], depth: u32) -> Result<Option<(PeelLayer, Vec<u8>)>> {
    let Some((inner_kind, body)): Option<(EvalKind, Vec<u8>)> = extract_eval_arg(buf) else {
        return Ok(None);
    };
    match inner_kind {
        EvalKind::Base64 => {
            let decoded: Vec<u8> =
                B64_STD
                    .decode(&body)
                    .map_err(|e: base64::DecodeError| Error::Base64Decode {
                        depth,
                        reason: e.to_string(),
                    })?;
            Ok(Some((PeelLayer::Base64Decode, decoded)))
        }
        EvalKind::GzInflate => {
            let inflated: Vec<u8> = inflate_raw(&body, depth)?;
            Ok(Some((PeelLayer::GzInflate, inflated)))
        }
        EvalKind::GzUncompress => {
            let inflated: Vec<u8> = inflate_zlib(&body, depth)?;
            Ok(Some((PeelLayer::GzUncompress, inflated)))
        }
        EvalKind::StrRot13 => {
            let rotated: Vec<u8> = body.iter().copied().map(rot13_byte).collect();
            Ok(Some((PeelLayer::StrRot13, rotated)))
        }
        EvalKind::StrReplace { from, to } => {
            let replaced: Vec<u8> = str_replace_bytes(&body, &from, &to);
            Ok(Some((PeelLayer::StrReplace, replaced)))
        }
        EvalKind::Plain => Ok(Some((PeelLayer::EvalUnwrap, body))),
    }
}

enum EvalKind {
    Base64,
    GzInflate,
    GzUncompress,
    StrRot13,
    StrReplace { from: Vec<u8>, to: Vec<u8> },
    Plain,
}

#[allow(clippy::expect_used)]
fn eval_outer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)(?:<\?(?:php)?\s*)?(?:eval|assert)\s*\(\s*(.+?)\s*\)\s*;?\s*(?:\?>)?\s*$")
            .expect("static eval regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn b64_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)^\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)\s*$"#)
            .expect("static b64 regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn gzinflate_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*gzinflate\s*\((.*)\)\s*$").expect("static gzinflate regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn gzuncompress_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*gzuncompress\s*\((.*)\)\s*$")
            .expect("static gzuncompress regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn rot13_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*str_rot13\s*\((.*)\)\s*$").expect("static rot13 regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn str_replace_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)^\s*str_replace\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"]([^'"]*)['"]\s*,\s*['"]([^'"]*)['"]\s*\)\s*$"#,
        )
        .expect("static str_replace regex compiles")
    })
}

fn extract_eval_arg(buf: &[u8]) -> Option<(EvalKind, Vec<u8>)> {
    let caps = eval_outer_re().captures(buf)?;
    let arg: &[u8] = caps.get(1)?.as_bytes();
    classify_inner(arg).or_else(|| {
        let trimmed: Vec<u8> = trim_quotes(arg);
        Some((EvalKind::Plain, trimmed))
    })
}

fn classify_inner(arg: &[u8]) -> Option<(EvalKind, Vec<u8>)> {
    if let Some(caps) = b64_call_re().captures(arg) {
        let body: Vec<u8> = caps
            .get(1)?
            .as_bytes()
            .iter()
            .copied()
            .filter(|b: &u8| !b.is_ascii_whitespace())
            .collect();
        return Some((EvalKind::Base64, body));
    }
    if let Some(caps) = gzinflate_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        let (inner_kind, decoded): (EvalKind, Vec<u8>) =
            classify_inner(inner_arg).unwrap_or_else(|| (EvalKind::Plain, trim_quotes(inner_arg)));
        let payload: Vec<u8> = if matches!(inner_kind, EvalKind::Base64) {
            B64_STD.decode(&decoded).ok().unwrap_or(decoded)
        } else {
            decoded
        };
        return Some((EvalKind::GzInflate, payload));
    }
    if let Some(caps) = gzuncompress_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        let (inner_kind, decoded): (EvalKind, Vec<u8>) =
            classify_inner(inner_arg).unwrap_or_else(|| (EvalKind::Plain, trim_quotes(inner_arg)));
        let payload: Vec<u8> = if matches!(inner_kind, EvalKind::Base64) {
            B64_STD.decode(&decoded).ok().unwrap_or(decoded)
        } else {
            decoded
        };
        return Some((EvalKind::GzUncompress, payload));
    }
    if let Some(caps) = rot13_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        let (_inner_kind, decoded): (EvalKind, Vec<u8>) =
            classify_inner(inner_arg).unwrap_or_else(|| (EvalKind::Plain, trim_quotes(inner_arg)));
        return Some((EvalKind::StrRot13, decoded));
    }
    if let Some(caps) = str_replace_call_re().captures(arg) {
        let from: Vec<u8> = caps.get(1)?.as_bytes().to_vec();
        let to: Vec<u8> = caps.get(2)?.as_bytes().to_vec();
        let body: Vec<u8> = caps.get(3)?.as_bytes().to_vec();
        return Some((EvalKind::StrReplace { from, to }, body));
    }
    None
}

fn trim_quotes(arg: &[u8]) -> Vec<u8> {
    let s: &[u8] = arg.trim_ascii();
    if s.len() >= 2 && (s[0] == b'\'' || s[0] == b'"') && s[s.len() - 1] == s[0] {
        return s[1..s.len() - 1].to_vec();
    }
    s.to_vec()
}

fn inflate_raw(body: &[u8], depth: u32) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len() * 3);
    let mut dec: DeflateDecoder<&[u8]> = DeflateDecoder::new(body);
    dec.read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::GzInflateFailed {
            depth,
            reason: e.to_string(),
        })?;
    Ok(out)
}

fn inflate_zlib(body: &[u8], depth: u32) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len() * 3);
    let mut dec: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(body);
    dec.read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::GzInflateFailed {
            depth,
            reason: e.to_string(),
        })?;
    Ok(out)
}

const fn rot13_byte(b: u8) -> u8 {
    match b {
        b'A'..=b'M' | b'a'..=b'm' => b + 13,
        b'N'..=b'Z' | b'n'..=b'z' => b - 13,
        other => other,
    }
}

fn str_replace_bytes(buf: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return buf.to_vec();
    }
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut i: usize = 0;
    while i < buf.len() {
        if buf[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
            continue;
        }
        out.push(buf[i]);
        i += 1;
    }
    out
}

fn contains_eval_call(buf: &[u8]) -> bool {
    memchr::memmem::find(buf, b"eval(").is_some() || memchr::memmem::find(buf, b"assert(").is_some()
}

#[allow(clippy::expect_used)]
fn peel_fopo(buf: &[u8], depth: u32) -> Result<Option<Vec<u8>>> {
    static MARKER_RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex = MARKER_RE.get_or_init(|| {
        Regex::new(
            r#"(?is)<\?php\s*/\*[^*]*FOPO[^*]*\*/.*?\$\w+\s*=\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*;.*?eval\s*\("#,
        )
        .expect("fopo regex compiles")
    });
    let Some(caps) = re.captures(buf) else {
        return Ok(None);
    };
    let blob: Vec<u8> = caps
        .get(1)
        .map(|m: regex::bytes::Match<'_>| {
            m.as_bytes()
                .iter()
                .copied()
                .filter(|b: &u8| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>()
        })
        .ok_or(Error::FopoPeel("missing payload capture"))?;
    let decoded: Vec<u8> =
        B64_STD
            .decode(&blob)
            .map_err(|e: base64::DecodeError| Error::Base64Decode {
                depth,
                reason: e.to_string(),
            })?;
    Ok(Some(decoded))
}

#[allow(clippy::expect_used)]
fn peel_better_php(buf: &[u8], depth: u32) -> Result<Option<Vec<u8>>> {
    static MARKER_RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex = MARKER_RE.get_or_init(|| {
        Regex::new(
            r#"(?is)<\?php\s*/\*[^*]*Better\s+PHP\s+Obfuscator[^*]*\*/\s*\$\w+\s*=\s*base64_decode\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)\s*;\s*\$\w+\s*=\s*gzinflate\(\s*\$\w+\s*\)\s*;\s*eval\s*\(\s*\$\w+\s*\)"#,
        )
        .expect("better-php regex compiles")
    });
    let Some(caps) = re.captures(buf) else {
        return Ok(None);
    };
    let blob: &[u8] = caps
        .get(1)
        .ok_or(Error::FopoPeel("missing payload"))?
        .as_bytes();
    let b64_clean: Vec<u8> = blob
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect();
    let decoded: Vec<u8> = B64_STD
        .decode(&b64_clean)
        .map_err(|e: base64::DecodeError| Error::Base64Decode {
            depth,
            reason: e.to_string(),
        })?;
    let inflated: Vec<u8> = inflate_raw(&decoded, depth)?;
    Ok(Some(inflated))
}
