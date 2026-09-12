#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
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
        "import py_compile; py_compile.compile(r'{}', cfile=r'{}', doraise=True)",
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

const LEADING_LITERAL_CF_CASES: &[(&str, &str)] = &[
    ("plain", "def s(x): return t\"hello {x}\"\n"),
    (
        "ternary",
        "def f(n): return t\"pre {n if n > 0 else -n}\"\n",
    ),
    ("or_chain", "def g(x,y,z): return t\"a {x or y} b {z}\"\n"),
    (
        "multi_lead",
        "def h(n): return t\"lead {n if n else 0} mid {n+1} end\"\n",
    ),
];

fn spurious_leading_literal(source: &str) -> Option<String> {
    for raw in source.lines() {
        let line: &str = raw.trim();
        if line.is_empty() || line.starts_with("def ") {
            continue;
        }
        let is_bare_string: bool = (line.starts_with('"')
            || line.starts_with('\'')
            || line.starts_with("f\"")
            || line.starts_with("f'")
            || line.starts_with("t\"")
            || line.starts_with("t'"))
            && (line.ends_with('"') || line.ends_with('\''))
            && !line.starts_with("return")
            && !line.contains('=');
        if line.starts_with("return") {
            return None;
        }
        if is_bare_string {
            return Some(raw.to_owned());
        }
    }
    None
}

#[test]
fn tstring_leading_literal_controlflow_3_14() {
    let Some(interp): Option<PathBuf> = find_interpreter("3.14") else {
        eprintln!("skip tstring_leading_literal_controlflow_3_14: no 3.14 interpreter");
        return;
    };
    let scratch: ScratchDir =
        ScratchDir::create("py-decompile-tstring-leading-literal").expect("scratch");
    let tmp: &Path = scratch.path();

    for (label, src) in LEADING_LITERAL_CF_CASES {
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

        if let Some(bad) = spurious_leading_literal(&decoded.source) {
            panic!(
                "case {label}: spurious leading bare string-literal statement {bad:?}\nsource:\n{}",
                decoded.source
            );
        }

        let rt_py: PathBuf = tmp.join(format!("{label}_rt.py"));
        let rt_pyc: PathBuf = tmp.join(format!("{label}_rt.pyc"));
        std::fs::write(&rt_py, &decoded.source).expect("write rt py");
        compile_source(&interp, &rt_py, &rt_pyc).unwrap_or_else(|e: String| {
            panic!("recompile {label} failed: {e}\nsource:\n{}", decoded.source)
        });

        let (orig, ver): (CodeObject, MarshalVersion) = read_code(&pyc).expect("read orig code");
        let (rt, _): (CodeObject, MarshalVersion) = read_code(&rt_pyc).expect("read rt code");
        let verdict: Verdict = semantic_equiv(&orig, &rt, ver);
        assert!(
            matches!(verdict, Verdict::Perfect | Verdict::Semantic),
            "case {label}: not semantically equivalent: {verdict:?}\nsource:\n{}",
            decoded.source
        );
    }
}
