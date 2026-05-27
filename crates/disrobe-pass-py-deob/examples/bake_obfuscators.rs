#![allow(clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_py_deob::obfuscators::{
    berserker, blankobf, jawbreaker, kramer, manglify, obfuxtreme, online_family, oxyry, plusobf,
    py_mauricelambert, pyminifier, pyobfuscate_com, python_obfuscator_pypi, wodx,
};

type BakeFn = fn(&str) -> String;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let out_root: PathBuf = args
        .get(1)
        .map_or_else(|| PathBuf::from("corpus/python/obfuscators"), PathBuf::from);

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
        let edge_dir: PathBuf = obf_dir.join("edge-cases");
        fs::create_dir_all(&edge_dir)
            .map_err(|e| format!("mkdir {disp}: {e}", disp = edge_dir.display()))?;
        let sample_src: &str = edge_cases
            .get("hello_world")
            .copied()
            .unwrap_or("print('hi')\n");
        let sample: String = bake_fn(sample_src);
        let sample_path: PathBuf = obf_dir.join("sample.py");
        write_idempotent(&sample_path, sample.as_bytes())?;
        total_files += 1;
        total_bytes += sample.len();
        for (case_name, src) in &edge_cases {
            let baked: String = bake_fn(src);
            let path: PathBuf = edge_dir.join(format!("{case_name}.py"));
            write_idempotent(&path, baked.as_bytes())?;
            total_files += 1;
            total_bytes += baked.len();
        }
    }
    println!(
        "[bake] obfuscators={} files={} bytes={}",
        baker_map.len(),
        total_files,
        total_bytes
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
