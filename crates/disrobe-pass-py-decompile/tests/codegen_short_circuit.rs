#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::too_many_lines,
    dead_code
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{DiffDetail, Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const REPORT_DIR: &str = "../../target/py-short-circuit";

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | "));
    }
    Ok(())
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn roundtrip(interpreter: &Path, alias: &str, name: &str, src: &str) -> (String, Verdict) {
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("scratch");
    let _ = fs::create_dir_all(&scratch);
    let source_path: PathBuf = scratch.join(format!("{name}.{alias}.py"));
    fs::write(&source_path, src).expect("write source");
    let orig_pyc: PathBuf = scratch.join(format!("{name}.{alias}.orig.pyc"));
    compile_source(interpreter, &source_path, &orig_pyc)
        .unwrap_or_else(|e| panic!("orig compile {name} {alias}: {e}"));
    let (original_code, marshal_version): (CodeObject, MarshalVersion) =
        read_code(&orig_pyc).unwrap_or_else(|e| panic!("read orig {name} {alias}: {e}"));
    let decompile_version: DecompileVersion = marshal_to_decompile(marshal_version)
        .unwrap_or_else(|e| panic!("version map {alias}: {e:?}"));
    let source: String = build_real_source(&original_code, &decompile_version, marshal_version)
        .unwrap_or_else(|e| panic!("decompile {name} {alias}: {e}"));
    let recovered_path: PathBuf = scratch.join(format!("{name}.{alias}.dec.py"));
    fs::write(&recovered_path, &source).expect("write recovered");
    let recompiled_pyc: PathBuf = scratch.join(format!("{name}.{alias}.dec.pyc"));
    match compile_source(interpreter, &recovered_path, &recompiled_pyc) {
        Ok(()) => {}
        Err(e) => return (source, Verdict::CodeDiff(recompile_fail(&e))),
    }
    let (recompiled_code, _): (CodeObject, MarshalVersion) = read_code(&recompiled_pyc)
        .unwrap_or_else(|e| panic!("read recompiled {name} {alias}: {e}"));
    let verdict: Verdict = semantic_equiv(&original_code, &recompiled_code, marshal_version);
    (source, verdict)
}

fn recompile_fail(msg: &str) -> DiffDetail {
    DiffDetail {
        qualname: "<recompile>".to_owned(),
        first_diff_offset: 0,
        original_op: "SYNTAX".to_owned(),
        recompiled_op: msg.chars().take(160).collect(),
        note: "recompile failed".to_owned(),
    }
}

const CASES: &[(&str, &str)] = &[
    (
        "if_and",
        "def f(a, b):\n    if a and b:\n        return 1\n    return 0\n",
    ),
    (
        "if_or",
        "def f(a, b):\n    if a or b:\n        return 1\n    return 0\n",
    ),
    (
        "if_and3",
        "def f(a, b, c):\n    if a and b and c:\n        return 1\n    return 0\n",
    ),
    (
        "if_mixed",
        "def f(a, b, c):\n    if a and b or c:\n        return 1\n    return 0\n",
    ),
    (
        "if_or_and",
        "def f(a, b, c):\n    if a or b and c:\n        return 1\n    return 0\n",
    ),
    (
        "if_paren_group",
        "def f(a, b, c, d):\n    if (a or b) and (c or d):\n        return 1\n    return 0\n",
    ),
    (
        "if_nested_group",
        "def f(a, b, c, d):\n    if a and (b or c) and d:\n        return 1\n    return 0\n",
    ),
    (
        "if_not_group",
        "def f(a, b):\n    if not (a and b):\n        return 1\n    return 0\n",
    ),
    (
        "while_or",
        "def f(a, b):\n    while a or b:\n        a = a - 1\n    return a\n",
    ),
    (
        "while_and",
        "def f(a, b):\n    while a and b:\n        a = a - 1\n    return a\n",
    ),
    (
        "while_mixed",
        "def f(a, b, c):\n    while a and b or c:\n        a = a - 1\n    return a\n",
    ),
    (
        "assert_and",
        "def f(a, b):\n    assert a and b\n    return 1\n",
    ),
    (
        "assert_or",
        "def f(a, b):\n    assert a or b\n    return 1\n",
    ),
    (
        "store_mixed",
        "def f(a, b, c):\n    x = a and b or c\n    return x\n",
    ),
    ("return_and", "def f(a, b):\n    return a and b\n"),
    (
        "return_mixed",
        "def f(a, b, c, d):\n    return a and b or c and d\n",
    ),
    (
        "ternary_and",
        "def f(a, b, c):\n    return b if a and c else 0\n",
    ),
    (
        "if_and_cmp",
        "def f(a, b):\n    if a > 0 and b > 0:\n        return 1\n    return 0\n",
    ),
    (
        "if_or_cmp",
        "def f(a, b):\n    if a > 0 or b > 0:\n        return 1\n    return 0\n",
    ),
    (
        "if_chain_cmp_and",
        "def f(a, b, c):\n    if a < b < c and a > 0:\n        return 1\n    return 0\n",
    ),
    (
        "elif_and",
        "def f(a, b, c):\n    if a and b:\n        return 1\n    elif b and c:\n        return 2\n    return 0\n",
    ),
    (
        "if_call_and",
        "def f(a, b):\n    if g(a) and h(b):\n        return 1\n    return 0\n\ndef g(x):\n    return x\n\ndef h(x):\n    return x\n",
    ),
    (
        "if_deep_mixed",
        "def f(a, b, c, d, e):\n    if (a and b) or (c and d) or e:\n        return 1\n    return 0\n",
    ),
    (
        "while_complex",
        "def f(a, b, c):\n    while (a or b) and c:\n        c = c - 1\n    return c\n",
    ),
];

fn run_matrix(alias: &str) {
    let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
        eprintln!("no {alias} interpreter; skipping");
        return;
    };
    let mut failures: Vec<String> = Vec::new();
    for (name, src) in CASES {
        let (source, verdict): (String, Verdict) = roundtrip(&interpreter, alias, name, src);
        let ok: bool = matches!(verdict, Verdict::Perfect | Verdict::Semantic);
        if !ok {
            println!("=== {alias} {name} [FAIL] ===");
            println!("{source}");
            println!("VERDICT: {verdict:?}\n");
            failures.push((*name).to_owned());
        }
    }
    assert!(
        failures.is_empty(),
        "[{alias}] short-circuit cases failed round-trip: {failures:?}"
    );
}

#[test]
fn short_circuit_3_10() {
    run_matrix("3.10");
}

#[test]
fn short_circuit_3_11() {
    run_matrix("3.11");
}

#[test]
fn short_circuit_3_12() {
    run_matrix("3.12");
}

#[test]
fn short_circuit_3_13() {
    run_matrix("3.13");
}

#[test]
fn short_circuit_3_14() {
    run_matrix("3.14");
}

#[test]
fn short_circuit_3_15() {
    run_matrix("3.15");
}
