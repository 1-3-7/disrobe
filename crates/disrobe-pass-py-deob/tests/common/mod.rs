#![allow(dead_code, unreachable_pub)]

use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;

pub fn corpus_root() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("obfuscators");
    p
}

fn resolve_slot(root: &Path, obf: &str, slot: &str) -> (PathBuf, String) {
    if let Some(variant) = slot.strip_prefix("variant_") {
        return (root.join(obf).join("variants"), variant.to_owned());
    }
    if slot.starts_with("edge_cases_") {
        return (root.join(obf), format!("real_{slot}"));
    }
    if let Some(edge) = slot.strip_prefix("edge_") {
        return (root.join(obf).join("edge-cases"), format!("real_{edge}"));
    }
    (root.join(obf), format!("real_{slot}"))
}

pub fn load_real_fixture(obf: &str, slot: &str) -> Option<Vec<u8>> {
    let root: PathBuf = corpus_root();
    let (dir, file_stem): (PathBuf, String) = resolve_slot(&root, obf, slot);
    let py_path: PathBuf = dir.join(format!("{file_stem}.py"));
    if let Ok(bytes) = std::fs::read(&py_path) {
        return Some(bytes);
    }
    let pyc_path: PathBuf = dir.join(format!("{file_stem}.pyc"));
    if let Ok(bytes) = std::fs::read(&pyc_path) {
        return Some(bytes);
    }
    let b64_path: PathBuf = dir.join(format!("{file_stem}.py.b64"));
    if let Ok(wrapped) = std::fs::read(&b64_path) {
        let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
        if let Ok(decoded) = engine.decode(wrapped.trim_ascii()) {
            return Some(decoded);
        }
    }
    let fixture_path: PathBuf = dir.join(format!("{file_stem}.py.fixture"));
    if let Ok(wrapped) = std::fs::read(&fixture_path) {
        let magic: &[u8] = b"DISROBE_OBFUSCATOR_FIXTURE_ZLIB_BASE64_V1";
        if let Some(rest) = wrapped.strip_prefix(magic) {
            let body: &[u8] = rest
                .strip_prefix(b"\r\n")
                .or_else(|| rest.strip_prefix(b"\n"))
                .unwrap_or(rest);
            let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
            if let Ok(b64_decoded) = engine.decode(body.trim_ascii()) {
                let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
                    flate2::read::ZlibDecoder::new(b64_decoded.as_slice());
                let mut out: Vec<u8> = Vec::new();
                if decoder.read_to_end(&mut out).is_ok() {
                    return Some(out);
                }
            }
        }
    }
    None
}

pub fn skip_absent_corpus(test_name: &str, obf: &str) {
    eprintln!(
        "skip: {test_name} ({obf} real corpus absent; dev-local fixture, regen via corpus/generate.sh)"
    );
}

/// Shared synthetic edge-case sources. These are clean inputs fed to a pass's own `bake()`
/// re-implementation; they are NOT real third-party-tool output. Anything driven through them via
/// `run_edge_cases` is a self-consistency smoke test only and does NOT gate real-recovery claims.
pub const EDGE_CASES: &[(&str, &str)] = &[
    ("hello_world", "print('hello world')\n"),
    (
        "recursive",
        "def fact(n):\n    if n <= 1:\n        return 1\n    return n * fact(n - 1)\n",
    ),
    (
        "class_decorator",
        "def deco(cls):\n    cls.decorated = True\n    return cls\n\n@deco\nclass Box:\n    def __init__(self, v):\n        self.v = v\n",
    ),
    (
        "async_fn",
        "import asyncio\n\nasync def fetch():\n    await asyncio.sleep(0)\n    return 1\n",
    ),
    (
        "generator",
        "def gen():\n    for i in range(3):\n        yield i\n",
    ),
    (
        "lambda_in_listcomp",
        "data = [(lambda y: y + 1)(x) for x in range(5)]\n",
    ),
    (
        "walrus_operator",
        "values = []\nwhile (n := input('? ')) != 'q':\n    values.append(n)\n",
    ),
    (
        "match_statement",
        "def shape_area(s):\n    match s:\n        case ('circle', r):\n            return 3.14 * r * r\n        case ('square', a):\n            return a * a\n        case _:\n            return 0\n",
    ),
    (
        "structural_pattern",
        "def kind(p):\n    match p:\n        case {'type': t, **_rest}:\n            return t\n        case _:\n            return None\n",
    ),
    (
        "typing_generic",
        "from typing import Generic, TypeVar\nT = TypeVar('T')\n\nclass Holder(Generic[T]):\n    def __init__(self, value: T) -> None:\n        self.value = value\n",
    ),
];

/// NON-GATING synthetic helper: bakes each `EDGE_CASES` source with the pass's own `bake()` and
/// asserts `peel()` accepts it. This validates the `bake()` -> `peel()` model round-trip only and
/// is CIRCULAR with respect to real-tool recovery (same author for both directions). Real-recovery
/// accuracy must be gated by the `<family>_real.rs` tests that read independent committed fixtures.
pub fn run_edge_cases<F: Fn(&str) -> String, P: Fn(&[u8]) -> bool>(bake: F, peel_ok: P) -> usize {
    let mut count: usize = 0;
    for (name, src) in EDGE_CASES {
        let obf: String = bake(src);
        assert!(peel_ok(obf.as_bytes()), "edge case {name} failed");
        count += 1;
    }
    count
}
