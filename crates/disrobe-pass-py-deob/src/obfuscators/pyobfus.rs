use std::collections::BTreeMap;

use disrobe_pass_py_disasm::{Instruction, disassemble, render_dis};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};

use crate::codec::{
    b16_decode, b32_decode, b64_decode, decode_python_bytes_literal,
    extract_largest_python_bytes_literal, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PyobfusPass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Base64,
    Base32,
    Base16,
    Zlib,
    Marshal,
}

impl Step {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Base32 => "base32",
            Self::Base16 => "base16",
            Self::Zlib => "zlib",
            Self::Marshal => "marshal",
        }
    }
}

const MARSHAL_VERSION: PyVersion = PyVersion::PY311;
const MAX_NESTED_CODE_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Chain {
    steps: Vec<Step>,
    reversed: bool,
}

fn parse_chain(text: &str) -> Option<Chain> {
    let lambda_start: usize = text.find("lambda")?;
    let exec_at: usize = text[lambda_start..].find("exec(")? + lambda_start;
    let body: &str = &text[lambda_start..exec_at];
    if !body.contains("__import__") {
        return None;
    }
    let reversed: bool = body.contains("[::-1]");
    let outer: Vec<Step> = ordered_steps(body);
    if outer.is_empty() {
        return None;
    }
    let mut inner_first: Vec<Step> = outer;
    inner_first.reverse();
    Some(Chain {
        steps: inner_first,
        reversed,
    })
}

fn ordered_steps(body: &str) -> Vec<Step> {
    const MARKERS: [(&str, Step); 5] = [
        ("marshal').loads", Step::Marshal),
        ("zlib').decompress", Step::Zlib),
        ("b64decode", Step::Base64),
        ("b32decode", Step::Base32),
        ("b16decode", Step::Base16),
    ];
    let mut found: Vec<(usize, Step)> = Vec::with_capacity(MARKERS.len());
    for (needle, step) in MARKERS {
        if let Some(pos) = body.find(needle) {
            found.push((pos, step));
        }
    }
    found.sort_by_key(|(pos, _): &(usize, Step)| *pos);
    found
        .into_iter()
        .map(|(_, step): (usize, Step)| step)
        .collect()
}

impl ObfuscatorPass for PyobfusPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Pyobfus
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let lambda_indirection: bool =
            text.contains("lambda") && text.contains("__import__") && text.contains("exec((_)(");
        let chain: Option<Chain> = parse_chain(text);
        let matched: bool = lambda_indirection && chain.is_some();
        let mut markers: Vec<String> = Vec::new();
        if lambda_indirection {
            markers.push("lambda-exec-indirection".to_owned());
        }
        if let Some(c) = &chain {
            if c.reversed {
                markers.push("reversed-payload".to_owned());
            }
            for step in &c.steps {
                markers.push(format!("decode-{}", step.label()));
            }
        }
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence: if matched { 0.9 } else { 0.0 },
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
        let chain: Chain = parse_chain(text).ok_or(Error::NoFamilyMatched)?;
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let mut payload: Vec<u8> = decode_python_bytes_literal(literal)?;

        let mut stages: Vec<String> = Vec::with_capacity(chain.steps.len() + 1);
        if chain.reversed {
            payload.reverse();
            stages.push("reverse".to_owned());
        }

        let mut terminal_marshal: bool = false;
        for step in &chain.steps {
            payload = match step {
                Step::Base64 => b64_decode(&payload)?,
                Step::Base32 => b32_decode(&payload)?,
                Step::Base16 => b16_decode(&payload)?,
                Step::Zlib => zlib_decompress(&payload)?,
                Step::Marshal => {
                    terminal_marshal = true;
                    payload
                }
            };
            stages.push(step.label().to_owned());
            if terminal_marshal {
                break;
            }
        }

        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("chain".to_owned(), chain_summary(&chain));
        diagnostics.insert("payload_bytes".to_owned(), payload.len().to_string());

        if terminal_marshal {
            return Ok(marshal_handoff(self.id(), stages, &payload, diagnostics));
        }

        let recovered: String = String::from_utf8(payload)
            .map_err(|e| Error::AstCleanup(format!("decoded payload is not utf-8 source: {e}")))?;
        diagnostics.insert("recovered_bytes".to_owned(), recovered.len().to_string());
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.95,
            quality: Quality::Full,
            lossy_notes: Vec::new(),
            diagnostics,
        })
    }
}

fn chain_summary(chain: &Chain) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(chain.steps.len() + 1);
    if chain.reversed {
        parts.push("reverse");
    }
    for step in &chain.steps {
        parts.push(step.label());
    }
    parts.join("->")
}

fn marshal_handoff(
    id: Obfuscator,
    stages: Vec<String>,
    marshalled: &[u8],
    mut diagnostics: BTreeMap<String, String>,
) -> PeelOutcome {
    match marshal_load(marshalled, MARSHAL_VERSION) {
        Ok(root) => {
            let mut top: Option<CodeObject> = None;
            let mut count: usize = 0;
            collect_code_objects(&root, &mut top, &mut count, 0);
            diagnostics.insert("code_objects".to_owned(), count.to_string());
            let listing: String = top
                .as_ref()
                .map(|co: &CodeObject| {
                    let ins: Vec<Instruction> = disassemble(co, MARSHAL_VERSION);
                    render_dis(&ins)
                })
                .unwrap_or_default();
            let entry: String = top
                .as_ref()
                .map(|co: &CodeObject| object_to_string(&co.name))
                .unwrap_or_default();
            diagnostics.insert("entry_code_object".to_owned(), entry.clone());
            let recovered: String = format!(
                "# disrobe: pyobfus marshal-terminated chain peeled to the embedded code object.\n# entry code object: {entry} ({count} total code objects).\n# inner is compiled bytecode, not source; bytecode disassembly follows. Run the py-decompile pass for source.\n{listing}\n"
            );
            PeelOutcome {
                obfuscator: id,
                stages_applied: stages,
                recovered_source: recovered,
                confidence: 0.9,
                quality: Quality::Partial,
                lossy_notes: vec![
                    "pyobfus marshal option embeds a code object, not source. The decode chain is fully recovered; source-level Python requires bytecode decompilation (py-decompile pass).".to_owned(),
                ],
                diagnostics,
            }
        }
        Err(e) => PeelOutcome {
            obfuscator: id,
            stages_applied: stages,
            recovered_source: String::new(),
            confidence: 0.6,
            quality: Quality::Partial,
            lossy_notes: vec![format!(
                "pyobfus marshal blob recovered but not parseable at the assumed Python version: {e}"
            )],
            diagnostics,
        },
    }
}

fn collect_code_objects(
    obj: &Object,
    top: &mut Option<CodeObject>,
    count: &mut usize,
    depth: usize,
) {
    if depth > MAX_NESTED_CODE_DEPTH {
        return;
    }
    match obj {
        Object::Code(co) => {
            if top.is_none() {
                *top = Some((**co).clone());
            }
            *count += 1;
            for c in &co.consts {
                collect_code_objects(c, top, count, depth + 1);
            }
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for c in items {
                collect_code_objects(c, top, count, depth + 1);
            }
        }
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (_, v) in d {
                collect_code_objects(v, top, count, depth + 1);
            }
        }
        _ => {}
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use disrobe_py_marshal::{CodeEra, dump as marshal_dump};
    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use super::*;
    use crate::codec::{b64_encode, python_bytes_literal};

    fn reverse(mut v: Vec<u8>) -> Vec<u8> {
        v.reverse();
        v
    }

    fn b16_encode_upper(input: &[u8]) -> String {
        const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut s: String = String::with_capacity(input.len() * 2);
        for b in input {
            s.push(UPPER_HEX[(b >> 4) as usize] as char);
            s.push(UPPER_HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    fn b32_encode_upper(input: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out: String = String::with_capacity(input.len().div_ceil(5) * 8);
        for chunk in input.chunks(5) {
            let mut buffer: [u8; 5] = [0u8; 5];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let bits: u64 = u64::from_be_bytes([
                0, 0, 0, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4],
            ]);
            let output_chars: usize = match chunk.len() {
                1 => 2,
                2 => 4,
                3 => 5,
                4 => 7,
                _ => 8,
            };
            for i in 0..8 {
                if i < output_chars {
                    let shift: u32 = 35 - (5 * i as u32);
                    let idx: usize = ((bits >> shift) & 0x1f) as usize;
                    out.push(ALPHABET[idx] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        let mut e: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(input).expect("zlib write");
        e.finish().expect("zlib finish")
    }

    fn wrap_base64(payload_reversed: &[u8]) -> String {
        let literal: String = python_bytes_literal(payload_reversed);
        format!("_ = lambda __ : __import__('base64').b64decode(__[::-1]);exec((_)({literal}))\n")
    }

    fn wrap_zlib_base64(payload_reversed: &[u8]) -> String {
        let literal: String = python_bytes_literal(payload_reversed);
        format!(
            "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)({literal}))\n"
        )
    }

    fn wrap_marshal_zlib_base64(payload_reversed: &[u8]) -> String {
        let literal: String = python_bytes_literal(payload_reversed);
        format!(
            "_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])));exec((_)({literal}))\n"
        )
    }

    #[test]
    fn peels_base64_reversed_to_exact_source() {
        let original: &str = "import os\nprint(os.getcwd())\n";
        let reversed_payload: Vec<u8> = reverse(b64_encode(original.as_bytes()).into_bytes());
        let stub: String = wrap_base64(&reversed_payload);
        assert!(PyobfusPass.detect(stub.as_bytes()).matched);
        let out: PeelOutcome = PyobfusPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.quality, Quality::Full);
        assert_eq!(out.recovered_source, original);
        assert_eq!(out.stages_applied, vec!["reverse", "base64"]);
    }

    #[test]
    fn peels_zlib_base64_reversed_to_exact_source() {
        let original: &str = "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n";
        let inner: Vec<u8> = b64_encode(&zlib_compress(original.as_bytes())).into_bytes();
        let stub: String = wrap_zlib_base64(&reverse(inner));
        let det: DetectReport = PyobfusPass.detect(stub.as_bytes());
        assert!(det.matched, "zlib+base64 reversed must match: {det:?}");
        let out: PeelOutcome = PyobfusPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.quality, Quality::Full);
        assert_eq!(out.recovered_source, original);
        assert_eq!(out.stages_applied, vec!["reverse", "base64", "zlib"]);
    }

    #[test]
    fn peels_base32_reversed_to_exact_source() {
        let original: &str = "print('b32 path')\n";
        let reversed_payload: Vec<u8> = reverse(b32_encode_upper(original.as_bytes()).into_bytes());
        let literal: String = python_bytes_literal(&reversed_payload);
        let stub: String = format!(
            "_ = lambda __ : __import__('base64').b32decode(__[::-1]);exec((_)({literal}))\n"
        );
        assert!(PyobfusPass.detect(stub.as_bytes()).matched);
        let out: PeelOutcome = PyobfusPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
        assert_eq!(out.stages_applied, vec!["reverse", "base32"]);
    }

    #[test]
    fn peels_base16_reversed_to_exact_source() {
        let original: &str = "x = 42\n";
        let reversed_payload: Vec<u8> = reverse(b16_encode_upper(original.as_bytes()).into_bytes());
        let literal: String = python_bytes_literal(&reversed_payload);
        let stub: String = format!(
            "_ = lambda __ : __import__('base64').b16decode(__[::-1]);exec((_)({literal}))\n"
        );
        let out: PeelOutcome = PyobfusPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
        assert_eq!(out.stages_applied, vec!["reverse", "base16"]);
    }

    #[test]
    fn peels_marshal_zlib_base64_to_disassembly_handoff() {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.name = Object::ShortAscii {
            value: "module".to_owned(),
            interned: false,
        };
        co.code = vec![0x97, 0x00, 0x64, 0x00, 0x53, 0x00];
        co.consts = vec![Object::None];
        let marshalled: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(co)), MARSHAL_VERSION).expect("dump");
        let inner: Vec<u8> = b64_encode(&zlib_compress(&marshalled)).into_bytes();
        let stub: String = wrap_marshal_zlib_base64(&reverse(inner));
        let det: DetectReport = PyobfusPass.detect(stub.as_bytes());
        assert!(det.matched);
        assert!(det.markers.iter().any(|m: &String| m == "decode-marshal"));
        let out: PeelOutcome = PyobfusPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.quality, Quality::Partial);
        assert_eq!(
            out.stages_applied,
            vec!["reverse", "base64", "zlib", "marshal"]
        );
        assert!(out.recovered_source.contains("module"));
        assert_eq!(
            out.diagnostics.get("entry_code_object").map(String::as_str),
            Some("module")
        );
    }

    #[test]
    fn clean_python_does_not_match() {
        let src: &[u8] = b"def f():\n    return 1\n";
        assert!(!PyobfusPass.detect(src).matched);
    }

    #[test]
    fn direct_call_pyobfuscate_com_form_is_not_claimed() {
        let src: &[u8] =
            b"exec(__import__('zlib').decompress(__import__('base64').b64decode(b'eJw=')))\n";
        assert!(
            !PyobfusPass.detect(src).matched,
            "non-lambda direct-call form belongs to the pyobfuscate.com pass"
        );
    }
}
