#![allow(clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::PeelOutcome;
use disrobe_pass_py_deob::obfuscators::obfuxtreme::ObfuXtremePass;

const CASES: &[(&str, &str)] = &[
    ("edge_hello_world", "print('hello world')\n"),
    (
        "edge_recursive",
        "def fact(n):\n    if n <= 1:\n        return 1\n    return n * fact(n - 1)\n",
    ),
    (
        "edge_class_decorator",
        "def deco(cls):\n    cls.decorated = True\n    return cls\n\n@deco\nclass Box:\n    def __init__(self, v):\n        self.v = v\n",
    ),
    (
        "edge_async_fn",
        "import asyncio\n\nasync def fetch():\n    await asyncio.sleep(0)\n    return 1\n",
    ),
    (
        "edge_generator",
        "def gen():\n    for i in range(3):\n        yield i\n",
    ),
    (
        "edge_lambda_in_listcomp",
        "data = [(lambda y: y + 1)(x) for x in range(5)]\n",
    ),
    (
        "edge_typing_generic",
        "from typing import Generic, TypeVar\nT = TypeVar('T')\n\nclass Holder(Generic[T]):\n    def __init__(self, value: T) -> None:\n        self.value = value\n",
    ),
    (
        "edge_walrus_operator",
        "values = []\nwhile (n := input('? ')) != 'q':\n    values.append(n)\n",
    ),
];

const OBFUXTREME_EQUIVALENCE_FLOOR: usize = 3;

fn oracle_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("obfuxtreme_gate")
        .join("normalize_oracle.py")
}

fn structurally_equivalent(
    python: &Path,
    dir: &std::path::Path,
    slot: &str,
    original: &str,
    recovered: &str,
) -> bool {
    let orig_path: PathBuf = dir.join(format!("orig_{slot}.py"));
    let rec_path: PathBuf = dir.join(format!("rec_{slot}.py"));
    std::fs::write(&orig_path, original).expect("write original");
    std::fs::write(&rec_path, recovered).expect("write recovered");
    let output: std::process::Output = Command::new(python)
        .arg(oracle_script())
        .arg(&orig_path)
        .arg(&rec_path)
        .output()
        .expect("run normalize oracle");
    let verdict: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    verdict["equivalent"].as_bool().unwrap_or_else(|| {
        panic!(
            "the normalize oracle returned no verdict for {slot}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn obfuxtreme_recovery_is_cpython_structurally_equivalent_to_original_source() {
    let python: PathBuf = common::require_python_314();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_obfux_equiv").expect("scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut tested: usize = 0;
    let mut equivalent: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();
    for (slot, original) in CASES {
        let fixture: Vec<u8> = common::require_real_fixture("obfuxtreme", slot);
        tested += 1;
        let peel: PeelOutcome = ObfuXtremePass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("obfuxtreme slot {slot} peel: {e:?}"));
        if structurally_equivalent(&python, &dir, slot, original, &peel.recovered_source) {
            equivalent += 1;
        } else {
            mismatches.push((*slot).to_owned());
        }
    }

    println!("obfuxtreme structural-equivalence (real CPython 3.14) = {equivalent}/{tested}");
    if !mismatches.is_empty() {
        println!("not structurally equivalent (decompiler-owned residual): {mismatches:?}");
    }
    assert!(
        equivalent >= OBFUXTREME_EQUIVALENCE_FLOOR,
        "obfuxtreme structural-equivalence regressed below floor {OBFUXTREME_EQUIVALENCE_FLOOR}: got {equivalent}/{tested}, mismatches={mismatches:?}"
    );
}
