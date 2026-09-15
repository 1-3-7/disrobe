use serde::Serialize;

use disrobe_core::codec::hex::nibble as hex_nibble;
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_disasm::{Instruction, JumpFitness, disassemble, jump_target_fitness};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};

use crate::codec::{
    b16_decode, b32_decode, b64_decode, b85_decode, bz2_decompress, gzip_decompress,
    lzma_decompress, zlib_decompress,
};
use crate::error::{Error, Result};

const UNKNOWN_OPNAME: &str = "<unknown>";
const MAX_CHAIN_DEPTH: usize = 16;
const MAX_NESTED_CODE_DEPTH: usize = 64;
const SEMANTIC_CANDIDATES: usize = 4;

const CANDIDATE_VERSIONS: [PyVersion; 30] = [
    PyVersion::PY315,
    PyVersion::PY314,
    PyVersion::PY313,
    PyVersion::PY312,
    PyVersion::PY311,
    PyVersion::PY310,
    PyVersion::PY39,
    PyVersion::PY38,
    PyVersion::PY37,
    PyVersion::PY36,
    PyVersion::PY35,
    PyVersion::PY34,
    PyVersion::PY33,
    PyVersion::PY32,
    PyVersion::PY31,
    PyVersion::PY30,
    PyVersion::PY27,
    PyVersion::PY26,
    PyVersion::PY25,
    PyVersion::PY24,
    PyVersion::PY23,
    PyVersion::PY22,
    PyVersion::PY21,
    PyVersion::PY20,
    PyVersion::PY16,
    PyVersion::PY15,
    PyVersion::PY14,
    PyVersion::PY13,
    PyVersion::PY11,
    PyVersion::PY10,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ChainOp {
    Base64,
    Base85,
    Base32,
    Base16,
    Zlib,
    Gzip,
    Bz2,
    Lzma,
    Marshal,
}

impl ChainOp {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Base85 => "base85",
            Self::Base32 => "base32",
            Self::Base16 => "base16",
            Self::Zlib => "zlib",
            Self::Gzip => "gzip",
            Self::Bz2 => "bz2",
            Self::Lzma => "lzma",
            Self::Marshal => "marshal",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MarshalLayer {
    pub depth: usize,
    pub version_major: u8,
    pub version_minor: u8,
    pub entry_name: String,
    pub code_objects: usize,
    pub bytecode_len: usize,
    pub recovered_directly: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarshalRecovery {
    pub chain: Vec<String>,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_inferred: bool,
    pub layers: Vec<MarshalLayer>,
    pub source: String,
}

#[must_use]
pub fn detect_marshal(source: &[u8]) -> f32 {
    let head: &[u8] = &source[..source.len().min(64 * 1024)];
    if looks_like_raw_marshal(head) {
        return 0.95;
    }
    let Ok(text): core::result::Result<&str, _> = core::str::from_utf8(head) else {
        return 0.0;
    };
    let imports_marshal: bool =
        text.contains("__import__('marshal')") || text.contains("__import__(\"marshal\")");
    let has_loads: bool = text.contains("marshal.loads(")
        || text.contains("marshal.load(")
        || text.contains("marshal . loads")
        || imports_marshal;
    if !has_loads {
        return 0.0;
    }
    let has_exec: bool = text.contains("exec(") || text.contains("eval(");
    if has_exec { 0.9 } else { 0.7 }
}

fn looks_like_raw_marshal(bytes: &[u8]) -> bool {
    if bytes.len() < 5 {
        return false;
    }
    let head: u8 = bytes[0] & 0x7F;
    if !matches!(head, b'c' | b'C') {
        return false;
    }
    for version in [PyVersion::PY312, PyVersion::PY39, PyVersion::PY27] {
        if let Ok(obj) = marshal_load(bytes, version)
            && first_code_object(&obj).is_some()
        {
            return true;
        }
    }
    false
}

pub fn recover_marshal(source: &[u8], hint: Option<PyVersion>) -> Result<MarshalRecovery> {
    let (blob, chain): (Vec<u8>, Vec<String>) = peel_to_marshal_blob(source)?;
    let (version, inferred): (PyVersion, bool) = match hint {
        Some(v) if loads_code(&blob, v) => (v, false),
        _ => infer_version(&blob).ok_or_else(|| {
            Error::Marshal("could not infer a Python version for the marshal blob".to_owned())
        })?,
    };
    let root: Object = marshal_load(&blob, version).map_err(|e| Error::Marshal(format!("{e}")))?;
    let top: CodeObject = first_code_object(&root)
        .ok_or_else(|| Error::Marshal("marshal payload held no code object".to_owned()))?;

    let mut layers: Vec<MarshalLayer> = Vec::new();
    let source_out: String = decompile_code(&top, version, 0, &mut layers)?;

    Ok(MarshalRecovery {
        chain,
        version_major: version.major,
        version_minor: version.minor,
        version_inferred: inferred,
        layers,
        source: source_out,
    })
}

fn decompile_code(
    code: &CodeObject,
    version: PyVersion,
    depth: usize,
    layers: &mut Vec<MarshalLayer>,
) -> Result<String> {
    let decompile_version: DecompileVersion = marshal_to_decompile(version)
        .map_err(|e| Error::Marshal(format!("unsupported version {version:?}: {e}")))?;
    let (source, recovered_directly): (String, bool) =
        match build_real_source(code, &decompile_version, version) {
            Ok(src) => (src, true),
            Err(err) => (disasm_listing(code, version, &format!("{err}")), false),
        };
    layers.push(MarshalLayer {
        depth,
        version_major: version.major,
        version_minor: version.minor,
        entry_name: object_to_string(&code.name),
        code_objects: count_code_objects(code),
        bytecode_len: code.code.len(),
        recovered_directly,
    });

    let mut out: String = source;
    if depth < MAX_NESTED_CODE_DEPTH {
        for nested in nested_marshal_blobs(code) {
            let Some((inner_version, _)): Option<(PyVersion, bool)> = infer_version(&nested) else {
                continue;
            };
            let Ok(inner_root): core::result::Result<Object, _> =
                marshal_load(&nested, inner_version)
            else {
                continue;
            };
            let Some(inner_code): Option<CodeObject> = first_code_object(&inner_root) else {
                continue;
            };
            let inner_src: String = decompile_code(&inner_code, inner_version, depth + 1, layers)?;
            out.push_str("\n# disrobe: nested marshal layer recovered below\n");
            out.push_str(&inner_src);
        }
    }
    Ok(out)
}

fn nested_marshal_blobs(code: &CodeObject) -> Vec<Vec<u8>> {
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    collect_nested_blobs(code, &mut blobs, 0);
    blobs
}

fn collect_nested_blobs(code: &CodeObject, blobs: &mut Vec<Vec<u8>>, depth: usize) {
    if depth > MAX_NESTED_CODE_DEPTH {
        return;
    }
    for konst in &code.consts {
        match konst {
            Object::Bytes(b) if looks_like_raw_marshal(b) => blobs.push(b.clone()),
            Object::String { value, .. } | Object::Unicode { value, .. } => {
                let raw: Vec<u8> = value.bytes().collect();
                if looks_like_raw_marshal(&raw) {
                    blobs.push(raw);
                }
            }
            Object::Code(inner) => collect_nested_blobs(inner, blobs, depth + 1),
            _ => {}
        }
    }
}

fn peel_to_marshal_blob(source: &[u8]) -> Result<(Vec<u8>, Vec<String>)> {
    if looks_like_raw_marshal(source) {
        return Ok((source.to_vec(), vec!["marshal".to_owned()]));
    }
    let text: &str = core::str::from_utf8(source).map_err(Error::from)?;
    let literal: Vec<u8> = extract_literal_bytes(text).ok_or(Error::LiteralNotFound)?;

    let mut current: Vec<u8> = literal;
    let mut chain: Vec<String> = Vec::new();
    for _ in 0..MAX_CHAIN_DEPTH {
        if looks_like_raw_marshal(&current) {
            chain.push(ChainOp::Marshal.label().to_owned());
            return Ok((current, chain));
        }
        let Some((op, decoded)): Option<(ChainOp, Vec<u8>)> = peel_one(&current) else {
            break;
        };
        chain.push(op.label().to_owned());
        current = decoded;
    }
    if looks_like_raw_marshal(&current) {
        chain.push(ChainOp::Marshal.label().to_owned());
        return Ok((current, chain));
    }
    Err(Error::Marshal(
        "could not reduce the wrapper to a marshal code-object blob".to_owned(),
    ))
}

fn peel_one(data: &[u8]) -> Option<(ChainOp, Vec<u8>)> {
    if let Ok(out) = zlib_decompress(data)
        && !out.is_empty()
    {
        return Some((ChainOp::Zlib, out));
    }
    if let Ok(out) = gzip_decompress(data)
        && !out.is_empty()
    {
        return Some((ChainOp::Gzip, out));
    }
    if let Ok(out) = bz2_decompress(data)
        && !out.is_empty()
    {
        return Some((ChainOp::Bz2, out));
    }
    if data.first() == Some(&0xFD)
        && let Ok(out) = lzma_decompress(data)
        && !out.is_empty()
    {
        return Some((ChainOp::Lzma, out));
    }
    if let Ok(out) = b64_decode(data)
        && plausible_next(&out)
    {
        return Some((ChainOp::Base64, out));
    }
    if let Ok(out) = b85_decode(data)
        && plausible_next(&out)
    {
        return Some((ChainOp::Base85, out));
    }
    if let Ok(out) = b32_decode(data)
        && plausible_next(&out)
    {
        return Some((ChainOp::Base32, out));
    }
    if let Ok(out) = b16_decode(data)
        && plausible_next(&out)
    {
        return Some((ChainOp::Base16, out));
    }
    None
}

fn plausible_next(decoded: &[u8]) -> bool {
    if decoded.len() < 4 {
        return false;
    }
    if looks_like_raw_marshal(decoded) {
        return true;
    }
    matches!(decoded.first(), Some(0x78 | 0x1F | 0xFD | b'B')) || is_b64ish(decoded)
}

fn is_b64ish(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes
            .iter()
            .take(64)
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

fn extract_literal_bytes(text: &str) -> Option<Vec<u8>> {
    if let Some(bytes) = largest_python_bytes_literal(text) {
        return Some(bytes);
    }
    largest_quoted_string(text).map(String::into_bytes)
}

fn largest_python_bytes_literal(text: &str) -> Option<Vec<u8>> {
    let mut best: Option<Vec<u8>> = None;
    let mut cursor: usize = 0;
    while let Some((decoded, next)) = next_bytes_literal(text, cursor) {
        if best
            .as_ref()
            .is_none_or(|b: &Vec<u8>| decoded.len() > b.len())
        {
            best = Some(decoded);
        }
        cursor = next;
    }
    best
}

fn next_bytes_literal(text: &str, cursor: usize) -> Option<(Vec<u8>, usize)> {
    let window: &str = text.get(cursor..)?;
    let rel: usize = window.find("b'").or_else(|| window.find("b\""))?;
    let idx: usize = cursor + rel;
    let opener: u8 = *text.as_bytes().get(idx + 1)?;
    let body_start: usize = idx + 2;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = scan_unescaped(rest.as_bytes(), opener)?;
    let lit: &str = rest.get(..end_off)?;
    Some((decode_python_byte_escapes(lit), body_start + end_off + 1))
}

fn largest_quoted_string(text: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for opener in [b'\'', b'"'] {
        let mut from: usize = 0;
        while let Some(rel) = text.get(from..).and_then(|w: &str| w.find(opener as char)) {
            let start: usize = from + rel + 1;
            let rest: &str = text.get(start..)?;
            let Some(end_off): Option<usize> = scan_unescaped(rest.as_bytes(), opener) else {
                break;
            };
            if let Some(lit) = rest.get(..end_off)
                && best.as_ref().is_none_or(|b: &String| lit.len() > b.len())
            {
                best = Some(lit.to_owned());
            }
            from = start + end_off + 1;
        }
    }
    best
}

fn scan_unescaped(bytes: &[u8], opener: u8) -> Option<usize> {
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == opener {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn decode_python_byte_escapes(s: &str) -> Vec<u8> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b != b'\\' || i + 1 >= bytes.len() {
            out.push(b);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'x' if i + 3 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 2]), hex_nibble(bytes[i + 3])) {
                    out.push((hi << 4) | lo);
                    i += 4;
                } else {
                    out.push(b);
                    i += 1;
                }
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'\'' => {
                out.push(b'\'');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct VersionFit {
    version: PyVersion,
    instructions: usize,
    jumps_all_valid: bool,
}

fn infer_version(blob: &[u8]) -> Option<(PyVersion, bool)> {
    let mut screened: Vec<VersionFit> = Vec::new();
    let mut seen: Vec<PyVersion> = Vec::new();
    for version in CANDIDATE_VERSIONS {
        if seen.contains(&version) {
            continue;
        }
        seen.push(version);
        let Ok(root): core::result::Result<Object, _> = marshal_load(blob, version) else {
            continue;
        };
        let Some(code): Option<CodeObject> = first_code_object(&root) else {
            continue;
        };
        let Some((unknown, total)): Option<(usize, usize)> = opcode_tree_stats(&code, version)
        else {
            continue;
        };
        if unknown > 0 || total == 0 {
            continue;
        }
        let fitness: JumpFitness = jump_target_fitness(&code, version);
        screened.push(VersionFit {
            version,
            instructions: total,
            jumps_all_valid: fitness.all_valid(),
        });
    }
    screened.sort_by(rank_fit);

    for fit in screened.iter().take(SEMANTIC_CANDIDATES) {
        if decompiles_cleanly(blob, fit.version) {
            return Some((fit.version, true));
        }
    }
    screened.first().map(|fit: &VersionFit| (fit.version, true))
}

fn rank_fit(a: &VersionFit, b: &VersionFit) -> core::cmp::Ordering {
    b.jumps_all_valid
        .cmp(&a.jumps_all_valid)
        .then_with(|| a.instructions.cmp(&b.instructions))
        .then_with(|| version_rank(a.version).cmp(&version_rank(b.version)))
}

fn version_rank(v: PyVersion) -> u16 {
    u16::from(v.major) * 100 + u16::from(v.minor)
}

fn opcode_tree_stats(code: &CodeObject, version: PyVersion) -> Option<(usize, usize)> {
    let instructions: Vec<Instruction> = disassemble(code, version);
    let mut unknown: usize = instructions
        .iter()
        .filter(|i: &&Instruction| i.opname == UNKNOWN_OPNAME)
        .count();
    let mut total: usize = instructions.len();
    if total == 0 && !code.code.is_empty() {
        return None;
    }
    for konst in &code.consts {
        if let Object::Code(inner) = konst {
            let (u, t): (usize, usize) = opcode_tree_stats(inner, version)?;
            unknown += u;
            total += t;
        }
    }
    Some((unknown, total))
}

fn loads_code(blob: &[u8], version: PyVersion) -> bool {
    marshal_load(blob, version)
        .ok()
        .and_then(|obj: Object| first_code_object(&obj))
        .is_some()
}

const DECOMPILE_SENTINELS: [&str; 3] = [
    "__DR_UNRECOVERED_TARGET__",
    "__DR_NULL__",
    "__DR_CHAIN_SENTINEL__",
];

fn decompiles_cleanly(blob: &[u8], version: PyVersion) -> bool {
    let Ok(root): core::result::Result<Object, _> = marshal_load(blob, version) else {
        return false;
    };
    let Some(code): Option<CodeObject> = first_code_object(&root) else {
        return false;
    };
    let Ok(decompile_version): core::result::Result<DecompileVersion, _> =
        marshal_to_decompile(version)
    else {
        return false;
    };
    let Ok(source): core::result::Result<String, _> =
        build_real_source(&code, &decompile_version, version)
    else {
        return false;
    };
    !source.trim().is_empty()
        && DECOMPILE_SENTINELS
            .iter()
            .all(|sentinel: &&str| !source.contains(sentinel))
}

pub(crate) fn load_code_from_marshal(blob: &[u8]) -> Option<(CodeObject, PyVersion)> {
    let (version, _inferred): (PyVersion, bool) = infer_version(blob)?;
    let root: Object = marshal_load(blob, version).ok()?;
    let top: CodeObject = first_code_object(&root)?;
    Some((top, version))
}

pub(crate) fn decompile_code_object(code: &CodeObject, version: PyVersion) -> Result<String> {
    let mut layers: Vec<MarshalLayer> = Vec::new();
    decompile_code(code, version, 0, &mut layers)
}

fn first_code_object(obj: &Object) -> Option<CodeObject> {
    match obj {
        Object::Code(co) => Some((**co).clone()),
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => items.iter().find_map(first_code_object),
        Object::Dict(d) | Object::FrozenDict(d) => d.values().find_map(first_code_object),
        _ => None,
    }
}

fn count_code_objects(code: &CodeObject) -> usize {
    let mut total: usize = 1;
    for konst in &code.consts {
        if let Object::Code(inner) = konst {
            total += count_code_objects(inner);
        }
    }
    total
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        Object::None => String::new(),
        other => format!("{other:?}"),
    }
}

fn disasm_listing(code: &CodeObject, version: PyVersion, reason: &str) -> String {
    let instructions: Vec<Instruction> = disassemble(code, version);
    let listing: String = disrobe_pass_py_disasm::render_dis(&instructions);
    format!(
        "# disrobe: marshal code object recovered for python {}.{}, but source-level decompile failed.\n# reason: {reason}\n# disassembly follows.\n{listing}\n",
        version.major, version.minor,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_plain_marshal_exec() {
        let src: &[u8] = b"import marshal\nexec(marshal.loads(b'c\\x00'))\n";
        assert!(detect_marshal(src) >= 0.9);
    }

    #[test]
    fn detect_clean_python_is_zero() {
        let src: &[u8] = b"import os\nprint(os.getcwd())\n";
        assert!(detect_marshal(src).abs() < f32::EPSILON);
    }

    #[test]
    fn hex_nibble_round_trip() {
        assert_eq!(hex_nibble(b'a'), Some(10));
        assert_eq!(hex_nibble(b'F'), Some(15));
        assert_eq!(hex_nibble(b'9'), Some(9));
        assert_eq!(hex_nibble(b'g'), None);
    }

    #[test]
    fn decode_byte_escapes_handles_hex_and_named() {
        let decoded: Vec<u8> = decode_python_byte_escapes("\\x00A\\n\\t\\\\");
        assert_eq!(decoded, vec![0x00, b'A', b'\n', b'\t', b'\\']);
    }
}
