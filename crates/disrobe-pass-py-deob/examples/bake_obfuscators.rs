#![allow(clippy::expect_used, clippy::print_stdout)]

//! Emit SYNTHETIC self-test vectors for each pass's `bake()` round-trip codec.
//!
//! These are NOT real obfuscator output and must never be treated as corpus: each pass's
//! `bake()` is an in-crate encoder that exercises the decode codec end-to-end, but its byte
//! format intentionally differs from the upstream tool (e.g. Kramer/Berserker upstream emit a
//! `class <Name>()` self-decryptor with a `_sparkle` token blob; `bake()` emits a compressed
//! marshalled marker). Real-tool fixtures live under `corpus/python/obfuscators/<obf>/real_*`
//! and are indexed in `corpus/python/obfuscators/MANIFEST.toml`; the `*_real.rs` integration
//! tests assert recovery against THOSE, not against `bake()`.
//!
//! Output is written under a `_synthetic_selftest/` root with a `# SYNTHETIC ... DO NOT TREAT AS
//! REAL CORPUS` header on every file, so the de-circularized corpus cannot be silently re-polluted.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_py_deob::obfuscators::{
    berserker, blankobf, jawbreaker, kramer, manglify, obfuxtreme, online_family, oxyry, plusobf,
    py_mauricelambert, pyminifier, pyobfuscate_com, python_obfuscator_pypi, wodx,
};

type BakeFn = fn(&str) -> String;

const SYNTHETIC_HEADER: &str = "# SYNTHETIC bake() self-test vector - NOT real obfuscator output. DO NOT TREAT AS REAL CORPUS.\n# Real fixtures: corpus/python/obfuscators/<obf>/real_* (see MANIFEST.toml).\n";

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let out_root: PathBuf = args.get(1).map_or_else(
        || PathBuf::from("corpus/python/obfuscators/_synthetic_selftest"),
        PathBuf::from,
    );

    let edge_cases: BTreeMap<&str, &str> = BTreeMap::from([
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
    ]);

    let baker_map: BTreeMap<&str, BakeFn> = BTreeMap::from([
        ("kramer", kramer::bake as BakeFn),
        ("berserker", berserker::bake),
        ("jawbreaker", jawbreaker::bake),
        ("blankobf", blankobf::bake),
        ("plusobf", plusobf::bake),
        ("wodx", wodx::bake),
        ("pyobfuscate_com", pyobfuscate_com::bake),
        ("pyobfuscator_mauricelambert", py_mauricelambert::bake),
        ("python_obfuscator_pypi", python_obfuscator_pypi::bake),
        ("obfuxtreme", obfuxtreme::bake),
        ("manglify", manglify::bake),
        ("oxyry", oxyry::bake),
        ("pyminifier", pyminifier::bake),
        ("online_family", online_family::bake),
    ]);

    let mut total_files: usize = 0;
    let mut total_bytes: usize = 0;
    for (obf_name, bake_fn) in &baker_map {
        let obf_dir: PathBuf = out_root.join(obf_name);
        fs::create_dir_all(&obf_dir)
            .map_err(|e| format!("mkdir {disp}: {e}", disp = obf_dir.display()))?;
        for (case_name, src) in &edge_cases {
            let baked: String = bake_fn(src);
            let labeled: String = format!("{SYNTHETIC_HEADER}{baked}");
            let path: PathBuf = obf_dir.join(format!("synthetic_{case_name}.py"));
            write_idempotent(&path, labeled.as_bytes())?;
            total_files += 1;
            total_bytes += labeled.len();
        }
    }
    println!(
        "[bake-synthetic] obfuscators={} files={} bytes={} root={}",
        baker_map.len(),
        total_files,
        total_bytes,
        out_root.display()
    );
    Ok(())
}

fn write_idempotent(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    fs::write(path, bytes).map_err(|e| format!("write {disp}: {e}", disp = path.display()))
}
