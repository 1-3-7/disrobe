use crate::error::{Error, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use disrobe_core::debug::DebugLog;
use flate2::read::DeflateDecoder;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::OnceLock;

pub const DEFAULT_MAX_DEPTH: u32 = 32;

pub const INFLATE_OUTPUT_CAP: usize = 256 * 1024 * 1024;

const INFLATE_INITIAL_CAP: usize = 64 * 1024;

const EVAL_PROBE_SCAN_FACTOR: usize = 8;

const EVAL_PROBE_MIN_BUDGET: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PeelLayer {
    Base64Decode,
    GzInflate,
    GzUncompress,
    GzDecode,
    StrRot13,
    StrRev,
    StrReplace,
    Strtr,
    UrlDecode,
    RawUrlDecode,
    HexEscape,
    PackHex,
    Hex2Bin,
    ChrConcat,
    Uudecode,
    SingleKeyXor,
    CreateFunction,
    EvalUnwrap,
    Fopo,
    BetterPhpObfuscator,
    ModernLoader,
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
    let dbg: DebugLog = DebugLog::for_scope("php");
    dbg.section("php.peel.nested-decode");
    dbg.kv("source_len", || source.len().to_string());
    let mut layers: Vec<PeelTrace> = Vec::new();
    let mut counts: BTreeMap<PeelLayer, u32> = BTreeMap::new();
    let mut current: Vec<u8> = source.to_vec();
    let mut depth: u32 = 0;

    loop {
        if depth >= options.max_depth {
            dbg.line(|| format!("depth {depth} >= max_depth {}: aborting", options.max_depth));
            return Err(Error::EvalChainDepthExceeded { depth });
        }
        let before_len: usize = current.len();
        let Some((layer, next)): Option<(PeelLayer, Vec<u8>)> = try_one_layer(&current, depth)?
        else {
            if options.stop_when_clean && depth > 0 {
                dbg.line(|| format!("clean after {depth} layer(s)"));
                break;
            }
            if depth == 0 {
                dbg.line(|| "no decode layer matched at depth 0: stuck".to_owned());
                return Err(Error::EvalChainStuck { depth });
            }
            break;
        };
        dbg.line(|| {
            format!(
                "layer {depth}: {layer:?} {before_len} -> {} bytes",
                next.len()
            )
        });
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
    dbg.kv("layers_peeled", || depth.to_string());
    dbg.kv("residual_eval", || residual_eval.to_string());
    dbg.kv("final_len", || current.len().to_string());
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
    if let Some(report) = crate::loader::peel_loader(buf, crate::loader::DEFAULT_LOADER_DEPTH) {
        return Ok(Some((PeelLayer::ModernLoader, report.recovered)));
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
        EvalKind::GzDecode => {
            let inflated: Vec<u8> = gunzip(&body, depth)?;
            Ok(Some((PeelLayer::GzDecode, inflated)))
        }
        EvalKind::StrRot13 => {
            let rotated: Vec<u8> = body.iter().copied().map(rot13_byte).collect();
            Ok(Some((PeelLayer::StrRot13, rotated)))
        }
        EvalKind::StrRev => {
            let reversed: Vec<u8> = body.iter().copied().rev().collect();
            Ok(Some((PeelLayer::StrRev, reversed)))
        }
        EvalKind::StrReplace { from, to } => {
            let replaced: Vec<u8> = str_replace_bytes(&body, &from, &to)?;
            Ok(Some((PeelLayer::StrReplace, replaced)))
        }
        EvalKind::Strtr { from, to } => {
            let translated: Vec<u8> = strtr_bytes(&body, &from, &to);
            Ok(Some((PeelLayer::Strtr, translated)))
        }
        EvalKind::UrlDecode => Ok(Some((PeelLayer::UrlDecode, url_decode(&body, true)))),
        EvalKind::RawUrlDecode => Ok(Some((PeelLayer::RawUrlDecode, url_decode(&body, false)))),
        EvalKind::HexEscape => Ok(Some((PeelLayer::HexEscape, decode_hex_escapes(&body)))),
        EvalKind::PackHex => {
            let unpacked: Vec<u8> = decode_hex_stream(&body)
                .ok_or(Error::FopoPeel("pack('H*') payload is not valid hex"))?;
            Ok(Some((PeelLayer::PackHex, unpacked)))
        }
        EvalKind::Hex2Bin => {
            let unpacked: Vec<u8> = decode_hex_stream(&body)
                .ok_or(Error::FopoPeel("hex2bin payload is not valid hex"))?;
            Ok(Some((PeelLayer::Hex2Bin, unpacked)))
        }
        EvalKind::ChrConcat => Ok(Some((PeelLayer::ChrConcat, body))),
        EvalKind::Uudecode => Ok(Some((PeelLayer::Uudecode, uudecode(&body)))),
        EvalKind::SingleKeyXor { key } => {
            let plain: Vec<u8> = xor_repeating(&body, &key);
            Ok(Some((PeelLayer::SingleKeyXor, plain)))
        }
        EvalKind::CreateFunction => Ok(Some((PeelLayer::CreateFunction, body))),
        EvalKind::Plain => Ok(Some((PeelLayer::EvalUnwrap, body))),
    }
}

enum EvalKind {
    Base64,
    GzInflate,
    GzUncompress,
    GzDecode,
    StrRot13,
    StrRev,
    StrReplace { from: Vec<u8>, to: Vec<u8> },
    Strtr { from: Vec<u8>, to: Vec<u8> },
    UrlDecode,
    RawUrlDecode,
    HexEscape,
    PackHex,
    Hex2Bin,
    ChrConcat,
    Uudecode,
    SingleKeyXor { key: Vec<u8> },
    CreateFunction,
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

#[allow(clippy::expect_used)]
fn strtr_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)^\s*strtr\s*\(\s*(.+?)\s*,\s*['"]([^'"]*)['"]\s*,\s*['"]([^'"]*)['"]\s*\)\s*$"#,
        )
        .expect("static strtr regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn single_arg_call_re(func: &str) -> Regex {
    Regex::new(&format!(r"(?is)^\s*{func}\s*\((.*)\)\s*$"))
        .expect("static single-arg regex compiles")
}

#[allow(clippy::expect_used)]
fn gzdecode_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| single_arg_call_re("gzdecode"))
}

#[allow(clippy::expect_used)]
fn strrev_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| single_arg_call_re("strrev"))
}

#[allow(clippy::expect_used)]
fn urldecode_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| single_arg_call_re("urldecode"))
}

#[allow(clippy::expect_used)]
fn rawurldecode_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| single_arg_call_re("rawurldecode"))
}

#[allow(clippy::expect_used)]
fn uudecode_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| single_arg_call_re("convert_uudecode"))
}

#[allow(clippy::expect_used)]
fn pack_hex_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)^\s*pack\s*\(\s*['"]H\*['"]\s*,\s*['"]([0-9A-Fa-f\s]+)['"]\s*\)\s*$"#)
            .expect("static pack-hex regex compiles")
    })
}

#[allow(clippy::expect_used)]
fn hex2bin_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| single_arg_call_re("hex2bin"))
}

#[allow(clippy::expect_used)]
fn createfunction_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)^\s*create_function\s*\(\s*['"][^'"]*['"]\s*,\s*(.*)\)\s*$"#)
            .expect("static create_function regex compiles")
    })
}

fn extract_eval_arg(buf: &[u8]) -> Option<(EvalKind, Vec<u8>)> {
    if let Some(caps) = eval_outer_re().captures(buf) {
        let arg: &[u8] = caps.get(1)?.as_bytes();
        return classify_inner(arg)
            .or_else(|| is_bare_string_literal(arg).then(|| (EvalKind::Plain, trim_quotes(arg))));
    }
    extract_embedded_eval_arg(buf)
}

fn extract_embedded_eval_arg(buf: &[u8]) -> Option<(EvalKind, Vec<u8>)> {
    let mut search_from: usize = 0;
    let mut scan_budget: usize = buf
        .len()
        .saturating_mul(EVAL_PROBE_SCAN_FACTOR)
        .max(EVAL_PROBE_MIN_BUDGET);
    while let Some(arg) = next_eval_call_arg(buf, &mut search_from, &mut scan_budget) {
        if let Some(classified) = classify_inner(&arg) {
            return Some(classified);
        }
    }
    None
}

fn next_eval_call_arg(
    buf: &[u8],
    search_from: &mut usize,
    scan_budget: &mut usize,
) -> Option<Vec<u8>> {
    loop {
        let rest: &[u8] = buf.get(*search_from..)?;
        *scan_budget = scan_budget.checked_sub(rest.len())?;
        let (rel, kw_len): (usize, usize) = find_eval_keyword(rest)?;
        let kw_end: usize = *search_from + rel + kw_len;
        let paren: usize = skip_ws_to_paren(buf, kw_end)?;
        *search_from = kw_end;
        match balanced_paren_arg(buf, paren) {
            Some((arg, close)) => {
                *scan_budget = scan_budget.checked_sub(close.saturating_sub(paren))?;
                return Some(arg);
            }
            None => {
                *scan_budget = scan_budget.checked_sub(buf.len().saturating_sub(paren))?;
            }
        }
    }
}

fn find_eval_keyword(rest: &[u8]) -> Option<(usize, usize)> {
    let eval_pos: Option<usize> = find_keyword_boundary(rest, b"eval");
    let assert_pos: Option<usize> = find_keyword_boundary(rest, b"assert");
    match (eval_pos, assert_pos) {
        (Some(e), Some(a)) if e <= a => Some((e, 4)),
        (Some(_e), Some(a)) => Some((a, 6)),
        (Some(e), None) => Some((e, 4)),
        (None, Some(a)) => Some((a, 6)),
        (None, None) => None,
    }
}

fn find_keyword_boundary(rest: &[u8], kw: &[u8]) -> Option<usize> {
    let mut from: usize = 0;
    loop {
        let rel: usize = memchr::memmem::find(rest.get(from..)?, kw)?;
        let at: usize = from + rel;
        let prev_ok: bool = at == 0 || !is_ident_byte(rest[at - 1]);
        if prev_ok {
            return Some(at);
        }
        from = at + 1;
    }
}

const fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn skip_ws_to_paren(buf: &[u8], mut i: usize) -> Option<usize> {
    while let Some(&b) = buf.get(i) {
        if b.is_ascii_whitespace() {
            i += 1;
        } else if b == b'(' {
            return Some(i);
        } else {
            return None;
        }
    }
    None
}

fn balanced_paren_arg(buf: &[u8], open: usize) -> Option<(Vec<u8>, usize)> {
    let mut depth: i32 = 0;
    let mut i: usize = open;
    let mut quote: Option<u8> = None;
    while let Some(&b) = buf.get(i) {
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 1;
                } else if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'\'' | b'"' => quote = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((buf.get(open + 1..i)?.to_vec(), i));
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    None
}

fn resolve_inner(arg: &[u8]) -> Vec<u8> {
    if let Some(caps) = b64_call_re().captures(arg)
        && let Some(m) = caps.get(1)
    {
        let clean: Vec<u8> = m
            .as_bytes()
            .iter()
            .copied()
            .filter(|b: &u8| !b.is_ascii_whitespace())
            .collect();
        if let Ok(decoded) = B64_STD.decode(&clean) {
            let decoded: Vec<u8> = decoded;
            return decoded;
        }
    }
    trim_quotes(arg)
}

fn resolve_arg(arg: &[u8], depth: u32) -> Option<Vec<u8>> {
    if depth > RESOLVE_DEPTH_CAP {
        return None;
    }
    if let Some(caps) = b64_wrap_call_re().captures(arg) {
        let inner: &[u8] = caps.get(1)?.as_bytes();
        let resolved: Vec<u8> = resolve_wrapped(inner, depth + 1);
        let clean: Vec<u8> = resolved
            .iter()
            .copied()
            .filter(|b: &u8| !b.is_ascii_whitespace())
            .collect();
        return B64_STD.decode(&clean).ok();
    }
    let (kind, body): (EvalKind, Vec<u8>) = classify_inner_at_depth(arg, depth)?;
    apply_transform(kind, body, depth)
}

#[allow(clippy::expect_used)]
fn b64_wrap_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*base64_decode\s*\((.*)\)\s*$")
            .expect("static b64-wrap regex compiles")
    })
}

fn apply_transform(kind: EvalKind, body: Vec<u8>, depth: u32) -> Option<Vec<u8>> {
    match kind {
        EvalKind::Base64 => B64_STD.decode(&body).ok(),
        EvalKind::GzInflate => inflate_raw(&body, depth).ok(),
        EvalKind::GzUncompress => inflate_zlib(&body, depth).ok(),
        EvalKind::GzDecode => gunzip(&body, depth).ok(),
        EvalKind::StrRot13 => Some(body.iter().copied().map(rot13_byte).collect()),
        EvalKind::StrRev => Some(body.iter().copied().rev().collect()),
        EvalKind::StrReplace { from, to } => str_replace_bytes(&body, &from, &to).ok(),
        EvalKind::Strtr { from, to } => Some(strtr_bytes(&body, &from, &to)),
        EvalKind::UrlDecode => Some(url_decode(&body, true)),
        EvalKind::RawUrlDecode => Some(url_decode(&body, false)),
        EvalKind::HexEscape => Some(decode_hex_escapes(&body)),
        EvalKind::PackHex | EvalKind::Hex2Bin => decode_hex_stream(&body),
        EvalKind::Uudecode => Some(uudecode(&body)),
        EvalKind::SingleKeyXor { key } => Some(xor_repeating(&body, &key)),
        EvalKind::ChrConcat | EvalKind::CreateFunction | EvalKind::Plain => Some(body),
    }
}

fn resolve_wrapped(inner_arg: &[u8], depth: u32) -> Vec<u8> {
    resolve_arg(inner_arg, depth + 1).unwrap_or_else(|| resolve_inner(inner_arg))
}

fn resolve_inner_full(inner_arg: &[u8], depth: u32) -> Vec<u8> {
    resolve_arg(inner_arg, depth).unwrap_or_else(|| resolve_inner(inner_arg))
}

const RESOLVE_DEPTH_CAP: u32 = 32;

fn classify_inner(arg: &[u8]) -> Option<(EvalKind, Vec<u8>)> {
    classify_inner_at_depth(arg, 0)
}

fn classify_inner_at_depth(arg: &[u8], depth: u32) -> Option<(EvalKind, Vec<u8>)> {
    if depth > RESOLVE_DEPTH_CAP {
        return None;
    }
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
    if let Some(caps) = b64_wrap_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        if let Some(joined) = join_string_literal_concat(inner_arg) {
            let clean: Vec<u8> = joined
                .iter()
                .copied()
                .filter(|b: &u8| !b.is_ascii_whitespace())
                .collect();
            if let Ok(decoded) = B64_STD.decode(&clean) {
                return Some((EvalKind::Plain, decoded));
            }
        }
        if !is_bare_string_literal(inner_arg) {
            let resolved: Vec<u8> = resolve_inner_full(inner_arg, depth + 1);
            let clean: Vec<u8> = resolved
                .iter()
                .copied()
                .filter(|b: &u8| !b.is_ascii_whitespace())
                .collect();
            if let Ok(decoded) = B64_STD.decode(&clean) {
                return Some((EvalKind::Plain, decoded));
            }
        }
    }
    if let Some(caps) = gzinflate_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        return Some((
            EvalKind::GzInflate,
            resolve_inner_full(inner_arg, depth + 1),
        ));
    }
    if let Some(caps) = gzuncompress_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        return Some((
            EvalKind::GzUncompress,
            resolve_inner_full(inner_arg, depth + 1),
        ));
    }
    if let Some(caps) = rot13_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        return Some((EvalKind::StrRot13, resolve_inner_full(inner_arg, depth + 1)));
    }
    if let Some(caps) = str_replace_call_re().captures(arg) {
        let from: Vec<u8> = caps.get(1)?.as_bytes().to_vec();
        let to: Vec<u8> = caps.get(2)?.as_bytes().to_vec();
        let body: Vec<u8> = caps.get(3)?.as_bytes().to_vec();
        return Some((EvalKind::StrReplace { from, to }, body));
    }
    if let Some(caps) = strtr_call_re().captures(arg) {
        let subject: Vec<u8> = resolve_inner_full(caps.get(1)?.as_bytes(), depth + 1);
        let from: Vec<u8> = caps.get(2)?.as_bytes().to_vec();
        let to: Vec<u8> = caps.get(3)?.as_bytes().to_vec();
        return Some((EvalKind::Strtr { from, to }, subject));
    }
    if let Some(caps) = gzdecode_call_re().captures(arg) {
        return Some((
            EvalKind::GzDecode,
            resolve_wrapped(caps.get(1)?.as_bytes(), depth),
        ));
    }
    if let Some(caps) = strrev_call_re().captures(arg) {
        return Some((
            EvalKind::StrRev,
            resolve_wrapped(caps.get(1)?.as_bytes(), depth),
        ));
    }
    if let Some(caps) = urldecode_call_re().captures(arg) {
        return Some((
            EvalKind::UrlDecode,
            resolve_wrapped(caps.get(1)?.as_bytes(), depth),
        ));
    }
    if let Some(caps) = rawurldecode_call_re().captures(arg) {
        return Some((
            EvalKind::RawUrlDecode,
            resolve_wrapped(caps.get(1)?.as_bytes(), depth),
        ));
    }
    if let Some(caps) = uudecode_call_re().captures(arg) {
        return Some((
            EvalKind::Uudecode,
            resolve_wrapped(caps.get(1)?.as_bytes(), depth),
        ));
    }
    if let Some(caps) = pack_hex_call_re().captures(arg) {
        let hex: Vec<u8> = caps
            .get(1)?
            .as_bytes()
            .iter()
            .copied()
            .filter(|b: &u8| !b.is_ascii_whitespace())
            .collect();
        return Some((EvalKind::PackHex, hex));
    }
    if let Some(caps) = hex2bin_call_re().captures(arg) {
        let resolved: Vec<u8> = resolve_inner_full(caps.get(1)?.as_bytes(), depth + 1);
        let hex: Vec<u8> = resolved
            .iter()
            .copied()
            .filter(|b: &u8| !b.is_ascii_whitespace())
            .collect();
        return Some((EvalKind::Hex2Bin, hex));
    }
    if let Some(caps) = createfunction_call_re().captures(arg) {
        let inner_arg: &[u8] = caps.get(1)?.as_bytes();
        let next_depth: u32 = depth.saturating_add(1);
        let (kind, body): (EvalKind, Vec<u8>) = classify_inner_at_depth(inner_arg, next_depth)
            .unwrap_or_else(|| (EvalKind::CreateFunction, resolve_inner(inner_arg)));
        return Some((kind, body));
    }
    if let Some((key, body)) = classify_single_key_xor(arg) {
        return Some((EvalKind::SingleKeyXor { key }, body));
    }
    if let Some(body) = classify_chr_concat(arg) {
        return Some((EvalKind::ChrConcat, body));
    }
    if let Some(body) = classify_hex_escape_literal(arg) {
        return Some((EvalKind::HexEscape, body));
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

fn is_bare_string_literal(arg: &[u8]) -> bool {
    let s: &[u8] = arg.trim_ascii();
    s.len() >= 2 && (s[0] == b'\'' || s[0] == b'"') && s[s.len() - 1] == s[0]
}

fn join_string_literal_concat(arg: &[u8]) -> Option<Vec<u8>> {
    let s: &[u8] = arg.trim_ascii();
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    let mut parts: usize = 0;
    while i < s.len() {
        while i < s.len() && s[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let quote: u8 = s[i];
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        i += 1;
        let body_start: usize = i;
        while i < s.len() && s[i] != quote {
            if s[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        if i >= s.len() {
            return None;
        }
        out.extend_from_slice(&s[body_start..i]);
        i += 1;
        parts += 1;
        while i < s.len() && s[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < s.len() {
            if s[i] != b'.' {
                return None;
            }
            i += 1;
        }
    }
    (parts >= 2).then_some(out)
}

fn inflate_bounded<R: std::io::Read>(mut dec: R, depth: u32) -> Result<Vec<u8>> {
    let cap_plus_one: u64 = INFLATE_OUTPUT_CAP as u64 + 1;
    let mut out: Vec<u8> = Vec::with_capacity(INFLATE_INITIAL_CAP);
    let read: u64 = std::io::Read::take(&mut dec, cap_plus_one)
        .read_to_end(&mut out)
        .map(|n: usize| n as u64)
        .map_err(|e: std::io::Error| Error::GzInflateFailed {
            depth,
            reason: e.to_string(),
        })?;
    if read > INFLATE_OUTPUT_CAP as u64 {
        return Err(Error::GzInflateBomb {
            depth,
            cap: INFLATE_OUTPUT_CAP,
        });
    }
    Ok(out)
}

fn inflate_raw(body: &[u8], depth: u32) -> Result<Vec<u8>> {
    inflate_bounded(DeflateDecoder::new(body), depth)
}

fn inflate_zlib(body: &[u8], depth: u32) -> Result<Vec<u8>> {
    inflate_bounded(flate2::read::ZlibDecoder::new(body), depth)
}

fn gunzip(body: &[u8], depth: u32) -> Result<Vec<u8>> {
    inflate_bounded(flate2::read::GzDecoder::new(body), depth)
}

fn url_decode(buf: &[u8], plus_is_space: bool) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut i: usize = 0;
    while i < buf.len() {
        match buf[i] {
            b'%' if i + 2 < buf.len() => {
                if let (Some(hi), Some(lo)) = (hex_nibble(buf[i + 1]), hex_nibble(buf[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

fn decode_hex_escapes(buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut i: usize = 0;
    while i < buf.len() {
        if buf[i] == b'\\' && i + 1 < buf.len() {
            match buf[i + 1] {
                b'x' | b'X' => {
                    let h1: Option<u8> = buf.get(i + 2).copied().and_then(hex_nibble);
                    let h2: Option<u8> = buf.get(i + 3).copied().and_then(hex_nibble);
                    match (h1, h2) {
                        (Some(hi), Some(lo)) => {
                            out.push((hi << 4) | lo);
                            i += 4;
                            continue;
                        }
                        (Some(hi), None) => {
                            out.push(hi);
                            i += 3;
                            continue;
                        }
                        _ => {}
                    }
                }
                b'0'..=b'7' => {
                    let mut value: u16 = 0;
                    let mut consumed: usize = 0;
                    while consumed < 3 {
                        let Some(d): Option<u8> = buf.get(i + 1 + consumed).copied() else {
                            break;
                        };
                        if !(b'0'..=b'7').contains(&d) {
                            break;
                        }
                        value = value * 8 + u16::from(d - b'0');
                        consumed += 1;
                    }
                    out.push(value as u8);
                    i += 1 + consumed;
                    continue;
                }
                _ => {}
            }
        }
        out.push(buf[i]);
        i += 1;
    }
    out
}

fn decode_hex_stream(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.is_empty() || !buf.len().is_multiple_of(2) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(buf.len() / 2);
    let mut chunks: core::slice::ChunksExact<'_, u8> = buf.chunks_exact(2);
    for pair in &mut chunks {
        let hi: u8 = hex_nibble(pair[0])?;
        let lo: u8 = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn uudecode(buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for line in buf.split(|&b: &u8| b == b'\n') {
        let line: &[u8] = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let count: u8 = uu_byte(line[0]);
        if count == 0 {
            break;
        }
        let mut produced: usize = 0;
        let data: &[u8] = &line[1..];
        for chunk in data.chunks(4) {
            if chunk.len() < 4 {
                break;
            }
            let b0: u8 = uu_byte(chunk[0]);
            let b1: u8 = uu_byte(chunk[1]);
            let b2: u8 = uu_byte(chunk[2]);
            let b3: u8 = uu_byte(chunk[3]);
            let triple: [u8; 3] = [(b0 << 2) | (b1 >> 4), (b1 << 4) | (b2 >> 2), (b2 << 6) | b3];
            for &byte in &triple {
                if produced < count as usize {
                    out.push(byte);
                    produced += 1;
                }
            }
        }
    }
    out
}

const fn uu_byte(c: u8) -> u8 {
    if c == b'`' {
        0
    } else {
        (c.wrapping_sub(b' ')) & 0x3f
    }
}

fn xor_repeating(buf: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return buf.to_vec();
    }
    buf.iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[allow(clippy::expect_used)]
fn classify_single_key_xor(arg: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex = RE.get_or_init(|| {
        Regex::new(
            r#"(?is)^\s*(?:\$?\w+)\s*\(\s*(base64_decode\s*\(\s*['"][^'"]*['"]\s*\)|['"][^'"]*['"])\s*,\s*['"]([^'"]+)['"]\s*\)\s*$"#,
        )
        .expect("static single-key-xor regex compiles")
    });
    let caps: regex::bytes::Captures<'_> = re.captures(arg)?;
    let payload: Vec<u8> = resolve_inner(caps.get(1)?.as_bytes());
    let key: Vec<u8> = caps.get(2)?.as_bytes().to_vec();
    Some((key, payload))
}

#[allow(clippy::expect_used)]
fn classify_chr_concat(arg: &[u8]) -> Option<Vec<u8>> {
    static TERM_RE: OnceLock<Regex> = OnceLock::new();
    let term_re: &Regex = TERM_RE.get_or_init(|| {
        Regex::new(r"(?is)chr\s*\(\s*([0-9A-Za-z_]+)\s*\)").expect("static chr regex compiles")
    });
    let trimmed: &[u8] = arg.trim_ascii();
    if !trimmed.starts_with(b"chr") {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut matched_any: bool = false;
    let mut cursor: usize = 0;
    for caps in term_re.captures_iter(arg) {
        let whole: regex::bytes::Match<'_> = caps.get(0)?;
        let gap: &[u8] = arg.get(cursor..whole.start())?.trim_ascii();
        if (matched_any && gap != b".") || (!matched_any && !gap.is_empty()) {
            return None;
        }
        let raw: &[u8] = caps.get(1)?.as_bytes();
        let value: i64 = crate::literal::parse_php_integer_literal(raw)?;
        let byte: u8 = u8::try_from(value.rem_euclid(256)).ok()?;
        out.push(byte);
        matched_any = true;
        cursor = whole.end();
    }
    if !arg.get(cursor..)?.trim_ascii().is_empty() {
        return None;
    }
    if matched_any { Some(out) } else { None }
}

fn classify_hex_escape_literal(arg: &[u8]) -> Option<Vec<u8>> {
    let s: &[u8] = arg.trim_ascii();
    if s.len() < 2 || s[0] != b'"' || s[s.len() - 1] != b'"' {
        return None;
    }
    let inner: &[u8] = &s[1..s.len() - 1];
    memchr::memmem::find(inner, b"\\x")?;
    Some(decode_hex_escapes(inner))
}

const fn rot13_byte(b: u8) -> u8 {
    match b {
        b'A'..=b'M' | b'a'..=b'm' => b + 13,
        b'N'..=b'Z' | b'n'..=b'z' => b - 13,
        other => other,
    }
}

fn strtr_bytes(subject: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let n: usize = from.len().min(to.len());
    let mut map: [Option<u8>; 256] = [None; 256];
    for i in 0..n {
        map[from[i] as usize] = Some(to[i]);
    }
    subject
        .iter()
        .map(|b: &u8| map[*b as usize].unwrap_or(*b))
        .collect()
}

const STR_REPLACE_OUTPUT_CAP: usize = INFLATE_OUTPUT_CAP;

fn str_replace_bytes(buf: &[u8], from: &[u8], to: &[u8]) -> Result<Vec<u8>> {
    str_replace_bytes_with_cap(buf, from, to, STR_REPLACE_OUTPUT_CAP)
}

fn str_replace_bytes_with_cap(buf: &[u8], from: &[u8], to: &[u8], cap: usize) -> Result<Vec<u8>> {
    if from.is_empty() {
        if buf.len() > cap {
            return Err(Error::StrReplaceExpansion { cap });
        }
        return Ok(buf.to_vec());
    }
    let mut out: Vec<u8> = Vec::with_capacity(buf.len().min(cap));
    let mut i: usize = 0;
    while i < buf.len() {
        if buf[i..].starts_with(from) {
            extend_checked(&mut out, to, cap)?;
            i += from.len();
            continue;
        }
        if out.len() == cap {
            return Err(Error::StrReplaceExpansion { cap });
        }
        out.push(buf[i]);
        i += 1;
    }
    Ok(out)
}

fn extend_checked(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Result<()> {
    let next: usize = out
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::StrReplaceExpansion { cap })?;
    if next > cap {
        return Err(Error::StrReplaceExpansion { cap });
    }
    out.extend_from_slice(bytes);
    Ok(())
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn balanced_paren_arg_respects_nested_calls_and_string_parens() {
        let buf: &[u8] = b"eval(f(g(')(')));rest";
        let open: usize = memchr::memmem::find(buf, b"(").expect("open paren");
        let (arg, close): (Vec<u8>, usize) =
            balanced_paren_arg(buf, open).expect("balanced extract");
        assert_eq!(arg, b"f(g(')('))");
        assert_eq!(buf[close], b')');
    }

    #[test]
    fn embedded_eval_is_found_when_surrounded_by_inline_html() {
        let payload: &[u8] = b"echo 'pwned';";
        let encoded: String = B64_STD.encode(payload);
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(b"<html>junk<?php eval(base64_decode('");
        blob.extend_from_slice(encoded.as_bytes());
        blob.extend_from_slice(b"')); ?>more html");
        let report: PeelReport = peel(&blob, PeelOptions::default()).expect("peeled");
        assert_eq!(report.final_source, payload);
    }

    #[test]
    fn keyword_match_requires_word_boundary() {
        assert!(find_keyword_boundary(b"retrieval(x)", b"eval").is_none());
        assert!(find_keyword_boundary(b" eval(x)", b"eval").is_some());
    }

    #[test]
    fn strtr_bytes_matches_php_last_write_wins_no_rechain() {
        assert_eq!(strtr_bytes(b"a", b"aa", b"xy"), b"y");
        assert_eq!(strtr_bytes(b"a", b"ab", b"bc"), b"b");
        assert_eq!(strtr_bytes(b"abc", b"abc", b"xyz"), b"xyz");
    }

    #[test]
    fn str_replace_expansion_is_bounded() {
        let err: Error = str_replace_bytes_with_cap(b"aaaa", b"a", b"bbb", 8).expect_err("cap");
        assert!(matches!(err, Error::StrReplaceExpansion { cap: 8 }));
    }

    #[test]
    fn inline_strtr_custom_alphabet_base64_eval_is_peeled() {
        let payload: &[u8] = b"echo 'pwned';";
        let std_alpha: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let rot_alpha: &[u8] = b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/";
        let encoded: Vec<u8> = B64_STD.encode(payload).into_bytes();
        let scrambled: Vec<u8> = strtr_bytes(&encoded, std_alpha, rot_alpha);
        let mut blob: Vec<u8> = b"<?php eval(base64_decode(strtr('".to_vec();
        blob.extend_from_slice(&scrambled);
        blob.extend_from_slice(b"', '");
        blob.extend_from_slice(rot_alpha);
        blob.extend_from_slice(b"', '");
        blob.extend_from_slice(std_alpha);
        blob.extend_from_slice(b"')));");
        let report: PeelReport = peel(&blob, PeelOptions::default()).expect("peeled");
        assert_eq!(report.final_source, payload);
    }

    #[test]
    fn inline_outer_strtr_eval_records_the_strtr_layer() {
        let payload: &[u8] = b"echo 'pwned';";
        let scrambled: Vec<u8> = strtr_bytes(payload, b"ep", b"pe");
        let mut blob: Vec<u8> = b"<?php eval(strtr('".to_vec();
        blob.extend_from_slice(&scrambled);
        blob.extend_from_slice(b"', 'ep', 'pe'));");
        let report: PeelReport = peel(&blob, PeelOptions::default()).expect("peeled");
        assert_eq!(report.final_source, payload);
        assert!(report.layer_counts.contains_key(&PeelLayer::Strtr));
    }

    #[test]
    fn inline_hex2bin_eval_is_peeled() {
        const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
        let payload: &[u8] = b"echo 'pwned';";
        let mut hex: String = String::with_capacity(payload.len() * 2);
        for byte in payload.iter().copied() {
            hex.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
            hex.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
        }
        let blob: Vec<u8> = format!("<?php eval(hex2bin('{hex}'));").into_bytes();
        let report: PeelReport = peel(&blob, PeelOptions::default()).expect("peeled");
        assert_eq!(report.final_source, payload);
        assert!(report.layer_counts.contains_key(&PeelLayer::Hex2Bin));
    }

    #[test]
    fn nested_create_function_classification_stops_at_depth_cap() {
        let payload: &[u8] = b"echo 'bounded';";
        let mut expr: String = format!("base64_decode('{}')", B64_STD.encode(payload));
        for _ in 0..RESOLVE_DEPTH_CAP + 8 {
            expr = format!("create_function('', {expr})");
        }

        let (kind, body): (EvalKind, Vec<u8>) =
            classify_inner(expr.as_bytes()).expect("outer create_function must classify");

        assert!(matches!(kind, EvalKind::CreateFunction));
        assert!(
            body.windows(b"create_function".len())
                .any(|window: &[u8]| window == b"create_function"),
            "depth cap must leave nested create_function source for a later bounded peel"
        );
    }

    #[test]
    fn deeply_nested_decode_calls_never_stack_overflow_classify() {
        const NESTING: usize = 10_000;
        let mut expr: Vec<u8> = Vec::with_capacity(NESTING * 11 + 8);
        for _ in 0..NESTING {
            expr.extend_from_slice(b"str_rot13(");
        }
        expr.extend_from_slice(b"'x'");
        expr.extend(std::iter::repeat_n(b')', NESTING));
        let _: Option<(EvalKind, Vec<u8>)> = classify_inner(&expr);
    }

    #[test]
    fn many_unterminated_eval_calls_are_bounded() {
        const COUNT: usize = 200_000;
        let mut buf: Vec<u8> = Vec::with_capacity(COUNT * 5);
        for _ in 0..COUNT {
            buf.extend_from_slice(b"eval(");
        }
        let result: Option<(EvalKind, Vec<u8>)> = extract_embedded_eval_arg(&buf);
        assert!(result.is_none());
    }
}
