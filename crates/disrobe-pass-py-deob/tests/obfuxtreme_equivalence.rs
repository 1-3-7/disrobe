#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]
mod common;

use std::path::PathBuf;
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

fn python_314() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        let ok: bool = Command::new(candidate)
            .args(["-c", "import sys;print(sys.version_info[:2]==(3,14))"])
            .output()
            .ok()
            .and_then(|out: std::process::Output| String::from_utf8(out.stdout).ok())
            .is_some_and(|s: String| s.trim() == "True");
        if ok {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn oracle_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("obfuxtreme_gate")
        .join("normalize_oracle.py")
}

fn structurally_equivalent(
    python: &str,
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
    verdict["equivalent"].as_bool().unwrap_or(false)
}

#[test]
fn obfuxtreme_recovery_is_cpython_structurally_equivalent_to_original_source() {
    let Some(python): Option<String> = python_314() else {
        eprintln!("skip: obfuxtreme equivalence oracle (python 3.14 absent)");
        return;
    };
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_obfux_equiv_{pid}",
        pid = std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let mut tested: usize = 0;
    let mut equivalent: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();
    for (slot, original) in CASES {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("obfuxtreme", slot) else {
            continue;
        };
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
    let _: std::io::Result<()> = std::fs::remove_dir_all(&dir);

    if tested == 0 {
        common::skip_absent_corpus(
            "obfuxtreme_recovery_is_cpython_structurally_equivalent_to_original_source",
            "obfuxtreme",
        );
        return;
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
