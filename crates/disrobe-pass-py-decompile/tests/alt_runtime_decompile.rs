#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::{NativeDecompile, decompile_micropython, decompile_pypy};

const MPY_HELLO: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");
const MPY_CONTROL_FLOW: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/control_flow.mpy");
const MPY_ITER_LOOPS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/iter_loops.mpy");
const PYPY27_METHODS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/methods.pypy27.pyc");
const PYPY39_LEGACY: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/hello_pypy39_legacy.pypy39.pyc");

fn locate_python() -> Option<PathBuf> {
    if let Some(found) = uv_python() {
        return Some(found);
    }
    for cand in ["python3", "python"] {
        if which_on_path(cand).is_some() {
            return Some(PathBuf::from(cand));
        }
    }
    None
}

fn uv_python() -> Option<PathBuf> {
    let out: std::process::Output = Command::new("uv")
        .args(["python", "find", "3.12"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for variant in [exe.to_owned(), format!("{exe}.exe")] {
            let candidate: PathBuf = dir.join(variant);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn recompiles_clean(source: &str) -> Option<bool> {
    let python: PathBuf = locate_python()?;
    let script: &str = "import sys; compile(sys.stdin.read(), '<recovered>', 'exec')";
    let mut child: std::process::Child = Command::new(&python)
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    {
        use std::io::Write as _;
        let stdin: &mut std::process::ChildStdin = child.stdin.as_mut()?;
        stdin.write_all(source.as_bytes()).ok()?;
    }
    let out: std::process::Output = child.wait_with_output().ok()?;
    if !out.status.success() {
        eprintln!(
            "recompile stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Some(out.status.success())
}

#[test]
fn micropython_hello_recovers_add_and_call() {
    let out: NativeDecompile = decompile_micropython(MPY_HELLO).expect("lift mpy hello");
    let src: &str = &out.source;
    assert!(out.recovered_directly, "hello must recover directly: {src}");
    assert!(src.contains("def add"), "missing add def in: {src}");
    assert!(src.contains("return"), "missing return in: {src}");
    assert!(src.contains("print"), "missing print call in: {src}");
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered mpy hello must recompile:\n{src}");
    }
}

#[test]
fn micropython_control_flow_recovers_range_for_and_branch() {
    let out: NativeDecompile =
        decompile_micropython(MPY_CONTROL_FLOW).expect("lift mpy control flow");
    let src: &str = &out.source;
    assert!(out.recovered_directly, "control_flow must recover: {src}");
    assert!(src.contains("def classify"), "missing classify: {src}");
    assert!(src.contains("for "), "missing for-loop: {src}");
    assert!(
        src.contains("range("),
        "range for-loop not recovered: {src}"
    );
    assert!(
        src.contains("if ") && src.contains("else"),
        "if/else not recovered: {src}"
    );
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered mpy control_flow must recompile:\n{src}");
    }
}

#[test]
fn micropython_iter_loops_recovers_both_for_forms() {
    let out: NativeDecompile = decompile_micropython(MPY_ITER_LOOPS).expect("lift iter loops");
    let src: &str = &out.source;
    assert!(src.contains("def walk"), "missing walk: {src}");
    assert!(src.contains("def counted"), "missing counted: {src}");
    assert!(
        src.contains("for ") && src.contains("range("),
        "range-for not recovered: {src}"
    );
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered mpy iter_loops must recompile:\n{src}");
    }
}

#[test]
fn pypy27_methods_recovers_source() {
    let out: NativeDecompile = decompile_pypy(PYPY27_METHODS).expect("decompile pypy27");
    let src: &str = &out.source;
    assert!(
        out.recovered_directly,
        "pypy27 must recover directly: {src}"
    );
    assert!(src.contains("def run"), "missing run def: {src}");
    assert!(src.contains("class Box"), "missing Box class: {src}");
    assert!(src.contains("def double"), "missing double method: {src}");
    assert!(
        src.contains(".double()"),
        "PyPy CALL_METHOD not recovered as method call: {src}"
    );
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered pypy27 source must recompile:\n{src}");
    }
}

#[test]
fn pypy39_legacy_recovers_source() {
    let out: NativeDecompile = decompile_pypy(PYPY39_LEGACY).expect("decompile pypy39 legacy");
    let src: &str = &out.source;
    assert!(out.recovered_directly, "pypy39 must recover: {src}");
    assert!(src.contains("def greet"), "missing greet def: {src}");
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered pypy39 source must recompile:\n{src}");
    }
}
