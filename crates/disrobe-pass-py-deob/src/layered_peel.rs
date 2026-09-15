use disrobe_core::{CascadeHit, CodecScheme, codec_blind_cascade, codec_decode};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};
use ruff_python_parser::{Mode, ParseOptions, parse};
use serde::Serialize;

use crate::cipher::validated_crib;
use crate::cipher::{
    KeyFinding, harvest_marshal_key_candidates, harvest_text_key_candidates, try_decipher,
    try_decipher_keyed, try_decipher_keyless,
};
use crate::codec::bytes_to_hex;
use crate::codec::{
    b16_decode, b32_decode, b64_decode, b85_decode, bz2_decompress, decode_python_bytes_literal,
    extract_largest_python_bytes_literal, gzip_decompress, lzma_alone_decompress, lzma_decompress,
    zlib_decompress,
};
use crate::debug::{dbg_enabled, dbg_hex, dbg_kv, dbg_line};
use crate::error::{Error, Result};
use crate::marshal::{decompile_code_object, load_code_from_marshal};
use crate::shuffled_base64::recover;

const DEFAULT_MAX_DEPTH: usize = 32;
const DEFAULT_MAX_CUMULATIVE: u64 = 2 * 1024 * 1024 * 1024;
const MIN_SOURCE_PRINTABLE_RATIO: usize = 90;

#[derive(Debug, Clone, Copy)]
pub struct PeelBudget {
    pub max_depth: usize,
    pub max_cumulative_bytes: u64,
}

impl Default for PeelBudget {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_cumulative_bytes: DEFAULT_MAX_CUMULATIVE,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerStep {
    pub decoder: String,
    pub byte_size_in: usize,
    pub byte_size_out: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WallReason {
    DepthExhausted,
    CumulativeBudget,
    KeyAbsent,
    Unresolved,
    AeadBody,
    RsaBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayeredPeel {
    pub steps: Vec<LayerStep>,
    pub key_findings: Vec<KeyFinding>,
    pub final_source: String,
    pub converged: bool,
    pub recovered: bool,
    pub reached_marshal: bool,
    pub version_major: u8,
    pub version_minor: u8,
    pub wall: Option<WallReason>,
}

#[derive(Debug, Clone, Copy)]
enum Classified {
    PlainSource,
    PycHeader,
    Marshal,
    Compressed(Compression),
    CribArtifact(&'static str),
    TextEncoded,
    Opaque,
}

impl Classified {
    fn label(self) -> String {
        match self {
            Self::PlainSource => "plain-source".to_owned(),
            Self::PycHeader => "pyc-header".to_owned(),
            Self::Marshal => "marshal".to_owned(),
            Self::Compressed(comp) => format!("compressed:{}", comp.label()),
            Self::CribArtifact(name) => format!("crib:{name}"),
            Self::TextEncoded => "text-encoded".to_owned(),
            Self::Opaque => "opaque".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Compression {
    Zlib,
    Gzip,
    Bz2,
    Xz,
    LzmaAlone,
}

impl Compression {
    fn apply(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Zlib => zlib_decompress(data),
            Self::Gzip => gzip_decompress(data),
            Self::Bz2 => bz2_decompress(data),
            Self::Xz => lzma_decompress(data),
            Self::LzmaAlone => lzma_alone_decompress(data),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Gzip => "gzip",
            Self::Bz2 => "bz2",
            Self::Xz => "xz",
            Self::LzmaAlone => "lzma-alone",
        }
    }
}

fn classify(data: &[u8]) -> Classified {
    if data.is_empty() {
        return Classified::Opaque;
    }
    if let Some(comp) = sniff_compression(data) {
        return Classified::Compressed(comp);
    }
    if looks_like_pyc_header(data) {
        return Classified::PycHeader;
    }
    if looks_like_marshal(data) {
        return Classified::Marshal;
    }
    if is_plain_source(data) {
        return Classified::PlainSource;
    }
    if let Some(name) = validated_crib(data) {
        return Classified::CribArtifact(name);
    }
    if is_base_alphabet(data) {
        return Classified::TextEncoded;
    }
    Classified::Opaque
}

fn sniff_compression(data: &[u8]) -> Option<Compression> {
    match data {
        [0x78, b1, ..]
            if (u16::from(0x78u8) * 256 + u16::from(*b1)) % 31 == 0
                && zlib_decompress(data).is_ok() =>
        {
            Some(Compression::Zlib)
        }
        [0x1f, 0x8b, 0x08, ..] => Some(Compression::Gzip),
        [0x42, 0x5a, 0x68, ..] => Some(Compression::Bz2),
        [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, ..] => Some(Compression::Xz),
        [0x5d, 0x00, 0x00, ..] => Some(Compression::LzmaAlone),
        _ => None,
    }
}

fn looks_like_pyc_header(data: &[u8]) -> bool {
    data.len() >= 20 && data[2] == 0x0d && data[3] == 0x0a && (data[0] != 0 || data[1] != 0)
}

fn looks_like_marshal(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    if (data[0] & 0x7f) != 0x63 {
        return false;
    }
    for version in [PyVersion::PY312, PyVersion::PY39, PyVersion::PY27] {
        if let Ok(obj) = marshal_load(data, version)
            && first_code(&obj).is_some()
        {
            return true;
        }
    }
    false
}

fn first_code(obj: &Object) -> Option<CodeObject> {
    match obj {
        Object::Code(co) => Some((**co).clone()),
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => items.iter().find_map(first_code),
        Object::Dict(d) | Object::FrozenDict(d) => d.values().find_map(first_code),
        _ => None,
    }
}

fn is_plain_source(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let printable: usize = data
        .iter()
        .filter(|&&b: &&u8| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        .count();
    if printable * 100 < data.len() * MIN_SOURCE_PRINTABLE_RATIO {
        return false;
    }
    let Ok(text): core::result::Result<&str, _> = core::str::from_utf8(data) else {
        return false;
    };
    if is_single_encoded_token(data) {
        return false;
    }
    parse(text, ParseOptions::from(Mode::Module)).is_ok() && text.trim().len() >= 3
}

fn is_single_encoded_token(data: &[u8]) -> bool {
    const MIN_TOKEN_LEN: usize = 24;
    data.len() >= MIN_TOKEN_LEN
        && is_base_alphabet(data)
        && data.iter().all(|&b: &u8| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

fn is_base_alphabet(data: &[u8]) -> bool {
    data.len() >= 8
        && data.iter().all(|&b: &u8| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'+' | b'/'
                        | b'='
                        | b'-'
                        | b'_'
                        | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'('
                        | b')'
                        | b'*'
                        | b';'
                        | b'<'
                        | b'>'
                        | b'?'
                        | b'@'
                        | b'^'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'\n'
                        | b'\r'
                        | b' '
                )
        })
}

fn oracle_accepts(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    sniff_compression(data).is_some()
        || looks_like_marshal(data)
        || looks_like_pyc_header(data)
        || is_plain_source(data)
        || validated_crib(data).is_some()
        || is_base_alphabet(data)
}

fn try_text_decode(data: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    let trimmed: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect();
    let probe: &[u8] = if trimmed.is_empty() { data } else { &trimmed };
    if let Ok(out) = b64_decode(probe)
        && oracle_accepts(&out)
    {
        return Some(("base64", out));
    }
    if let Ok(out) = b85_decode(probe)
        && oracle_accepts(&out)
    {
        return Some(("base85", out));
    }
    if let Ok(out) = b32_decode(probe)
        && oracle_accepts(&out)
    {
        return Some(("base32", out));
    }
    if let Ok(out) = b16_decode(probe)
        && oracle_accepts(&out)
    {
        return Some(("base16", out));
    }
    None
}

fn try_text_decode_lenient(data: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    let trimmed: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect();
    let probe: &[u8] = if trimmed.is_empty() { data } else { &trimmed };
    if let Ok(out) = b64_decode(probe)
        && out.len() >= 8
        && high_entropy(&out)
    {
        return Some(("base64", out));
    }
    if let Ok(out) = b85_decode(probe)
        && out.len() >= 8
        && high_entropy(&out)
    {
        return Some(("base85", out));
    }
    None
}

fn high_entropy(data: &[u8]) -> bool {
    let printable: usize = data
        .iter()
        .filter(|&&b: &&u8| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        .count();
    printable * 100 < data.len() * MIN_SOURCE_PRINTABLE_RATIO
}

fn codec_oracle_accepts(data: &[u8]) -> bool {
    data.len() >= 4
        && (sniff_compression(data).is_some()
            || looks_like_marshal(data)
            || looks_like_pyc_header(data)
            || is_plain_source(data)
            || validated_crib(data).is_some())
}

fn try_core_codec(data: &[u8]) -> Option<(String, Vec<u8>)> {
    for &scheme in CodecScheme::all() {
        let Ok(decoded): core::result::Result<Vec<u8>, _> = codec_decode(data, scheme) else {
            continue;
        };
        if !decoded.is_empty() && decoded.as_slice() != data && codec_oracle_accepts(&decoded) {
            return Some((format!("codec:{}", scheme.label()), decoded));
        }
    }
    for hit in codec_blind_cascade(data) {
        let CascadeHit {
            scheme, decoded, ..
        }: CascadeHit = hit;
        if decoded.as_slice() != data && is_plain_source(&decoded) {
            return Some((format!("codec:{}", scheme.label()), decoded));
        }
    }
    None
}

fn all_candidates(
    data: &[u8],
    text_candidates: &[Vec<u8>],
    hint: Option<PyVersion>,
) -> Vec<Vec<u8>> {
    let mut candidates: Vec<Vec<u8>> = text_candidates.to_vec();
    candidates.extend(harvest_marshal_candidates(data, hint));
    candidates
}

fn strip_pyc_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 16 {
        return None;
    }
    data.get(16..)
}

pub(crate) fn peel_layers(
    input: &[u8],
    hint: Option<PyVersion>,
    budget: &PeelBudget,
) -> Result<LayeredPeel> {
    let mut current: Vec<u8> = extract_entry_payload(input);
    let mut steps: Vec<LayerStep> = Vec::new();
    let mut key_findings: Vec<KeyFinding> = Vec::new();
    let mut cumulative: u64 = current.len() as u64;
    let text_candidates: Vec<Vec<u8>> = core::str::from_utf8(input)
        .ok()
        .map(harvest_text_key_candidates)
        .unwrap_or_default();

    for depth in 0..budget.max_depth {
        let classification: Classified = classify(&current);
        dbg_kv("layer-classify", || {
            format!(
                "depth={depth} len={len} -> {label}",
                len = current.len(),
                label = classification.label()
            )
        });
        match classification {
            Classified::PlainSource => {
                return Ok(finish_source(
                    String::from_utf8_lossy(&current).into_owned(),
                    steps,
                    key_findings,
                    true,
                    false,
                    PyVersion::PY312,
                ));
            }
            Classified::PycHeader => {
                if let Some(body) = strip_pyc_header(&current) {
                    let body_vec: Vec<u8> = body.to_vec();
                    push_step(&mut steps, "pyc-strip", current.len(), body_vec.len());
                    current = body_vec;
                    continue;
                }
                break;
            }
            Classified::Marshal => {
                return finalize_marshal(&current, hint, steps, key_findings);
            }
            Classified::Compressed(comp) => {
                let out: Vec<u8> = comp.apply(&current)?;
                cumulative = cumulative.saturating_add(out.len() as u64);
                if cumulative > budget.max_cumulative_bytes {
                    return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
                }
                push_step(&mut steps, comp.label(), current.len(), out.len());
                current = out;
                continue;
            }
            Classified::CribArtifact(name) => {
                dbg_kv("carve", || {
                    format!("crib={name} len={len}", len = current.len())
                });
                push_step(
                    &mut steps,
                    &format!("carve:{name}"),
                    current.len(),
                    current.len(),
                );
                return Ok(finish_artifact(&current, name, steps, key_findings));
            }
            Classified::TextEncoded => {
                if let Some((label, out)) = try_text_decode(&current) {
                    dbg_kv("text-decode", || {
                        format!(
                            "alphabet={label} {bin} -> {bout}",
                            bin = current.len(),
                            bout = out.len()
                        )
                    });
                    cumulative = cumulative.saturating_add(out.len() as u64);
                    if cumulative > budget.max_cumulative_bytes {
                        return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
                    }
                    push_step(&mut steps, label, current.len(), out.len());
                    current = out;
                    continue;
                }
                if let Some(recovery) = recover(&current) {
                    dbg_kv("shuffled-base64", || {
                        format!(
                            "crib={crib} recovered={recovered}/64 alphabet={alphabet}",
                            crib = recovery.crib,
                            recovered = recovery.recovered_symbols,
                            alphabet = recovery.alphabet_string(),
                        )
                    });
                    cumulative = cumulative.saturating_add(recovery.plaintext.len() as u64);
                    if cumulative > budget.max_cumulative_bytes {
                        return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
                    }
                    let label: String = format!(
                        "base64-shuffled:{crib}:{recovered}/64:{alphabet}",
                        crib = recovery.crib,
                        recovered = recovery.recovered_symbols,
                        alphabet = recovery.alphabet_string(),
                    );
                    push_step(&mut steps, &label, current.len(), recovery.plaintext.len());
                    current = recovery.plaintext;
                    continue;
                }
                if let Some((label, decoded)) = try_text_decode_lenient(&current) {
                    let candidates: Vec<Vec<u8>> = all_candidates(&decoded, &text_candidates, hint);
                    if let Some(result) = try_decipher(&decoded, &candidates) {
                        cumulative = cumulative.saturating_add(result.plaintext.len() as u64);
                        if cumulative > budget.max_cumulative_bytes {
                            return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
                        }
                        push_step(&mut steps, label, current.len(), decoded.len());
                        push_step(
                            &mut steps,
                            &result.finding.decoder_label(),
                            decoded.len(),
                            result.plaintext.len(),
                        );
                        key_findings.push(result.finding);
                        current = result.plaintext;
                        continue;
                    }
                }
            }
            Classified::Opaque => {}
        }

        let candidates: Vec<Vec<u8>> = all_candidates(&current, &text_candidates, hint);
        if dbg_enabled() {
            dbg_kv("key-candidates", || {
                format!(
                    "count={n} at len={len}",
                    n = candidates.len(),
                    len = current.len()
                )
            });
        }
        if let Some(result) = try_decipher_keyed(&current, &candidates) {
            cumulative = cumulative.saturating_add(result.plaintext.len() as u64);
            if cumulative > budget.max_cumulative_bytes {
                return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
            }
            push_step(
                &mut steps,
                &result.finding.decoder_label(),
                current.len(),
                result.plaintext.len(),
            );
            key_findings.push(result.finding);
            current = result.plaintext;
            continue;
        }

        if let Some((label, out)) = try_core_codec(&current) {
            cumulative = cumulative.saturating_add(out.len() as u64);
            if cumulative > budget.max_cumulative_bytes {
                return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
            }
            push_step(&mut steps, &label, current.len(), out.len());
            current = out;
            continue;
        }

        if let Some(result) = try_decipher_keyless(&current) {
            cumulative = cumulative.saturating_add(result.plaintext.len() as u64);
            if cumulative > budget.max_cumulative_bytes {
                return Ok(wall(steps, key_findings, WallReason::CumulativeBudget));
            }
            push_step(
                &mut steps,
                &result.finding.decoder_label(),
                current.len(),
                result.plaintext.len(),
            );
            key_findings.push(result.finding);
            current = result.plaintext;
            continue;
        }

        if depth + 1 == budget.max_depth {
            dbg_line(|| "wall: depth exhausted".to_owned());
            return Ok(wall(steps, key_findings, WallReason::DepthExhausted));
        }
        let reason: WallReason = classify_opaque_wall(&current);
        dbg_kv("wall", || {
            format!("{reason:?} at len={len}", len = current.len())
        });
        dbg_hex("wall-head", &current, 32);
        return Ok(wall(steps, key_findings, reason));
    }

    dbg_line(|| "wall: depth exhausted".to_owned());
    Ok(wall(steps, key_findings, WallReason::DepthExhausted))
}

fn classify_opaque_wall(data: &[u8]) -> WallReason {
    if data.len() < 28 {
        return WallReason::Unresolved;
    }
    let mut freq: [u32; 256] = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let unique: usize = freq.iter().filter(|&&c: &&u32| c > 0).count();
    if unique < 200 {
        return WallReason::Unresolved;
    }
    if matches!(data.len(), 128 | 256 | 512) {
        return WallReason::RsaBody;
    }
    let rem_after_nonce: usize = data.len().saturating_sub(12);
    if rem_after_nonce > 16 && rem_after_nonce.is_multiple_of(16) {
        return WallReason::AeadBody;
    }
    WallReason::Unresolved
}

fn harvest_marshal_candidates(data: &[u8], hint: Option<PyVersion>) -> Vec<Vec<u8>> {
    let versions: [PyVersion; 4] = hint.map_or(
        [
            PyVersion::PY312,
            PyVersion::PY313,
            PyVersion::PY311,
            PyVersion::PY39,
        ],
        |v: PyVersion| [v, PyVersion::PY312, PyVersion::PY39, PyVersion::PY27],
    );
    for version in versions {
        let Ok(obj): core::result::Result<Object, _> = marshal_load(data, version) else {
            continue;
        };
        let Some(code): Option<CodeObject> = first_code(&obj) else {
            continue;
        };
        let mut found: Vec<Vec<u8>> = Vec::new();
        collect_const_bytes(&code, &mut found, 0);
        if !found.is_empty() {
            return harvest_marshal_key_candidates(found);
        }
    }
    Vec::new()
}

fn collect_const_bytes(code: &CodeObject, out: &mut Vec<Vec<u8>>, depth: usize) {
    if depth > 16 {
        return;
    }
    for konst in &code.consts {
        match konst {
            Object::Bytes(b) => out.push(b.clone()),
            Object::String { value, .. }
            | Object::Unicode { value, .. }
            | Object::ShortAscii { value, .. } => {
                out.push(value.clone().into_bytes());
            }
            Object::Code(inner) => collect_const_bytes(inner, out, depth + 1),
            _ => {}
        }
    }
}

fn finalize_marshal(
    blob: &[u8],
    hint: Option<PyVersion>,
    mut steps: Vec<LayerStep>,
    key_findings: Vec<KeyFinding>,
) -> Result<LayeredPeel> {
    let (code, version): (CodeObject, PyVersion) = match hint {
        Some(v) => match load_code_from_marshal_with(blob, v) {
            Some(pair) => pair,
            None => load_code_from_marshal(blob)
                .ok_or_else(|| Error::Marshal("marshal blob held no code object".to_owned()))?,
        },
        None => load_code_from_marshal(blob)
            .ok_or_else(|| Error::Marshal("marshal blob held no code object".to_owned()))?,
    };
    let source: String = decompile_code_object(&code, version)?;
    dbg_kv("marshal-unwrap", || {
        format!(
            "version={major}.{minor} blob={blob} -> source={src}",
            major = version.major,
            minor = version.minor,
            blob = blob.len(),
            src = source.len()
        )
    });
    push_step(&mut steps, "marshal", blob.len(), source.len());
    Ok(finish_source(
        source,
        steps,
        key_findings,
        true,
        true,
        version,
    ))
}

fn load_code_from_marshal_with(blob: &[u8], version: PyVersion) -> Option<(CodeObject, PyVersion)> {
    let obj: Object = marshal_load(blob, version).ok()?;
    let code: CodeObject = first_code(&obj)?;
    Some((code, version))
}

fn extract_entry_payload(input: &[u8]) -> Vec<u8> {
    if classify_is_terminal_or_layer(input) {
        return input.to_vec();
    }
    let Ok(text): core::result::Result<&str, _> = core::str::from_utf8(input) else {
        return input.to_vec();
    };
    if let Some(lit) = extract_largest_python_bytes_literal(text)
        && let Ok(decoded) = decode_python_bytes_literal(lit)
        && decoded.len() >= 8
    {
        return decoded;
    }
    input.to_vec()
}

fn classify_is_terminal_or_layer(input: &[u8]) -> bool {
    matches!(
        classify(input),
        Classified::Compressed(_) | Classified::Marshal | Classified::PycHeader
    )
}

fn push_step(steps: &mut Vec<LayerStep>, decoder: &str, byte_size_in: usize, byte_size_out: usize) {
    steps.push(LayerStep {
        decoder: decoder.to_owned(),
        byte_size_in,
        byte_size_out,
    });
}

fn finish_artifact(
    data: &[u8],
    crib: &'static str,
    steps: Vec<LayerStep>,
    key_findings: Vec<KeyFinding>,
) -> LayeredPeel {
    let preview_len: usize = data.len().min(32);
    let summary: String = format!(
        "# recovered embedded {crib} artifact: {len} bytes\n# leading bytes: {hex}\n",
        len = data.len(),
        hex = bytes_to_hex(&data[..preview_len]),
    );
    LayeredPeel {
        steps,
        key_findings,
        final_source: summary,
        converged: true,
        recovered: true,
        reached_marshal: false,
        version_major: 0,
        version_minor: 0,
        wall: None,
    }
}

const fn finish_source(
    final_source: String,
    steps: Vec<LayerStep>,
    key_findings: Vec<KeyFinding>,
    recovered: bool,
    reached_marshal: bool,
    version: PyVersion,
) -> LayeredPeel {
    LayeredPeel {
        steps,
        key_findings,
        final_source,
        converged: true,
        recovered,
        reached_marshal,
        version_major: version.major,
        version_minor: version.minor,
        wall: None,
    }
}

const fn wall(
    steps: Vec<LayerStep>,
    key_findings: Vec<KeyFinding>,
    reason: WallReason,
) -> LayeredPeel {
    LayeredPeel {
        steps,
        key_findings,
        final_source: String::new(),
        converged: false,
        recovered: false,
        reached_marshal: false,
        version_major: 0,
        version_minor: 0,
        wall: Some(reason),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cipher::rc4_apply;
    use crate::codec::{b64_encode, xor_apply, zlib_compress};

    fn plain_source() -> &'static str {
        "def f(x):\n    return x + 1\nprint(f(41))\n"
    }

    #[test]
    fn standard_base64_zip_layers_to_carved_artifact() {
        let mut zip: Vec<u8> = vec![0x50, 0x4b, 0x03, 0x04, 0x14, 0x00];
        zip.extend_from_slice(&[0u8; 24]);
        zip.extend_from_slice(b"payload.txtdata bytes here for the local file entry");
        let token: String = b64_encode(&zip);
        let result: LayeredPeel =
            peel_layers(token.as_bytes(), None, &PeelBudget::default()).expect("peel");
        assert!(result.recovered, "steps: {:?}", result.steps);
        let labels: Vec<&str> = result.steps.iter().map(|s| s.decoder.as_str()).collect();
        assert!(labels.contains(&"base64"), "labels: {labels:?}");
        assert!(labels.iter().any(|l: &&str| l.contains("carve:zip")));
        assert!(result.final_source.contains("zip"));
    }

    #[test]
    fn plain_source_converges_without_layers() {
        let result: LayeredPeel =
            peel_layers(plain_source().as_bytes(), None, &PeelBudget::default()).expect("peel");
        assert!(result.converged);
        assert!(result.recovered);
        assert!(result.steps.is_empty());
        assert!(result.final_source.contains("return x + 1"));
    }

    #[test]
    fn base64_zlib_text_layers_peel_to_source() {
        let inner: &str = "x = 10\nprint(x * 2)\n";
        let z: Vec<u8> = zlib_compress(inner.as_bytes());
        let b64: String = b64_encode(&z);
        let result: LayeredPeel =
            peel_layers(b64.as_bytes(), None, &PeelBudget::default()).expect("peel");
        assert!(result.recovered, "steps: {:?}", result.steps);
        assert!(result.final_source.contains("print(x * 2)"));
        let labels: Vec<&str> = result.steps.iter().map(|s| s.decoder.as_str()).collect();
        assert!(labels.contains(&"base64"));
        assert!(labels.contains(&"zlib"));
    }

    #[test]
    fn xor_zlib_loader_recovers_via_sibling_key_literal() {
        let inner: &str = "def g():\n    return 7\n";
        let z: Vec<u8> = zlib_compress(inner.as_bytes());
        let key: &[u8] = b"k3yval";
        let xored: Vec<u8> = xor_apply(&z, key);
        let literal: String = crate::codec::python_bytes_literal(&xored);
        let loader: String = format!(
            "import zlib\nKEY = b'k3yval'\nexec(zlib.decompress(bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate({literal}))))\n"
        );
        let result: LayeredPeel =
            peel_layers(loader.as_bytes(), None, &PeelBudget::default()).expect("peel");
        assert!(result.recovered, "steps: {:?}", result.steps);
        assert!(result.final_source.contains("return 7"));
        assert_eq!(result.key_findings.len(), 1);
        assert_eq!(result.key_findings[0].key_hex, "6b337976616c");
    }

    #[test]
    fn xor_single_byte_keyless_recovers() {
        let inner: &str = "def g():\n    return 7\n";
        let z: Vec<u8> = zlib_compress(inner.as_bytes());
        let key: u8 = 0x5e;
        let xored: Vec<u8> = z.iter().map(|b: &u8| b ^ key).collect();
        let b64: String = b64_encode(&xored);
        let result: LayeredPeel =
            peel_layers(b64.as_bytes(), None, &PeelBudget::default()).expect("peel");
        assert!(result.recovered, "steps: {:?}", result.steps);
        assert!(result.final_source.contains("return 7"));
        assert_eq!(result.key_findings.len(), 1);
        assert_eq!(
            result.key_findings[0].cipher,
            crate::cipher::CipherKind::XorSingle
        );
    }

    #[test]
    fn rc4_loader_recovers_via_sibling_key_literal() {
        let inner: &str = "class C:\n    pass\n";
        let z: Vec<u8> = zlib_compress(inner.as_bytes());
        let key: &[u8] = b"rc4secretkey";
        let ct: Vec<u8> = rc4_apply(&z, key);
        let literal: String = crate::codec::python_bytes_literal(&ct);
        let loader: String = format!(
            "import rc4, zlib, marshal\nKEY = 'rc4secretkey'\nexec(zlib.decompress(rc4.decrypt({literal}, KEY)))\n"
        );
        let result: LayeredPeel =
            peel_layers(loader.as_bytes(), None, &PeelBudget::default()).expect("peel");
        assert!(result.recovered, "steps: {:?}", result.steps);
        assert!(result.final_source.contains("class C"));
        assert_eq!(result.key_findings.len(), 1);
        assert_eq!(
            result.key_findings[0].cipher,
            crate::cipher::CipherKind::Rc4
        );
    }

    #[test]
    fn cumulative_budget_aborts_bomb() {
        let bomb_inner: Vec<u8> = vec![0u8; 4 * 1024 * 1024];
        let z: Vec<u8> = zlib_compress(&bomb_inner);
        let budget: PeelBudget = PeelBudget {
            max_depth: 32,
            max_cumulative_bytes: 1024,
        };
        let result: LayeredPeel = peel_layers(&z, None, &budget).expect("peel");
        assert!(!result.recovered);
        assert_eq!(result.wall, Some(WallReason::CumulativeBudget));
    }
}
