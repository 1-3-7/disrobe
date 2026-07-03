#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_decompile::engine::{NativeDecompile, decompile_pyc};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{
    CodeObject, Object, PyVersion as MarshalVersion, PycFile, pyversion_from_magic, read_pyc,
};

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn compile_source(interpreter: &Path, source: &Path, pyc: &Path) -> Result<(), String> {
    let script: String = format!(
        "import py_compile,sys; py_compile.compile(r'{}', cfile=r'{}', doraise=True)",
        source.display(),
        pyc.display()
    );
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", &script])
        .output()
        .map_err(|e: std::io::Error| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn read_code(pyc: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = std::fs::read(pyc).map_err(|e: std::io::Error| e.to_string())?;
    let parsed: PycFile = read_pyc(&bytes).map_err(|e| format!("{e:?}"))?;
    let version: MarshalVersion = pyversion_from_magic(parsed.header.magic)
        .ok_or_else(|| format!("unknown magic 0x{:08x}", parsed.header.magic))?;
    match parsed.code {
        Object::Code(boxed) => Ok((*boxed, version)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

const PROOF_CASES: &[(&str, &str)] = &[
    ("plain", "x = 1\ndef f():\n    return t\"{x}\"\n"),
    (
        "conv_and_nested_spec",
        "x = 1\nw = 5\ndef f():\n    return t\"{x!r:>{w}}\"\n",
    ),
    ("debug_eq", "x = 1\ndef f():\n    return t\"{x=}\"\n"),
    (
        "multi_literal",
        "a = 1\nb = 2\ndef f():\n    return t\"a {a} mid {b!s} end\"\n",
    ),
    ("empty_spec", "x = 1\ndef f():\n    return t\"{x!r:}\"\n"),
];

#[test]
fn tstring_decode_roundtrip_3_14() {
    let Some(interp): Option<PathBuf> = find_interpreter("3.14") else {
        eprintln!("skip tstring_decode_roundtrip_3_14: no 3.14 interpreter");
        return;
    };
    let tmp: PathBuf = env::temp_dir().join("disrobe_tstr_proof");
    std::fs::create_dir_all(&tmp).expect("mk tmp");

    for (label, src) in PROOF_CASES {
        let py: PathBuf = tmp.join(format!("{label}.py"));
        let pyc: PathBuf = tmp.join(format!("{label}.pyc"));
        std::fs::write(&py, src).expect("write py");
        compile_source(&interp, &py, &pyc)
            .unwrap_or_else(|e: String| panic!("compile {label}: {e}"));

        let bytes: Vec<u8> = std::fs::read(&pyc).expect("read pyc");
        let decoded: NativeDecompile =
            decompile_pyc(&bytes).unwrap_or_else(|e| panic!("decompile {label}: {e}"));
        assert!(
            decoded.recovered_directly,
            "case {label}: fell back to disasm: {:?}\n{}",
            decoded.fallback_reason, decoded.source
        );
        println!("=== {label} ===\n{}", decoded.source);
        assert!(
            decoded.source.contains("t\""),
            "case {label}: recovered source has no t-string:\n{}",
            decoded.source
        );

        let recompiled_py: PathBuf = tmp.join(format!("{label}_rt.py"));
        let recompiled_pyc: PathBuf = tmp.join(format!("{label}_rt.pyc"));
        std::fs::write(&recompiled_py, &decoded.source).expect("write rt py");
        compile_source(&interp, &recompiled_py, &recompiled_pyc).unwrap_or_else(|e: String| {
            panic!("recompile {label} failed: {e}\nsource:\n{}", decoded.source)
        });

        let (orig, ver): (CodeObject, MarshalVersion) = read_code(&pyc).expect("read orig code");
        let (rt, _): (CodeObject, MarshalVersion) =
            read_code(&recompiled_pyc).expect("read rt code");
        let verdict: Verdict = semantic_equiv(&orig, &rt, ver);
        assert!(
            matches!(verdict, Verdict::Perfect | Verdict::Semantic),
            "case {label}: not semantically equivalent: {verdict:?}\nsource:\n{}",
            decoded.source
        );
    }
}
