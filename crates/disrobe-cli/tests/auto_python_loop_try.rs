#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SOURCE: &str = r#"def guarded_read():
    while active():
        if primary() or secondary():
            try:
                sink(read())
            except LookupError:
                sink(None)
            continue
        sink("ready")
"#;

fn python_312() -> PathBuf {
    if let Ok(output) = Command::new("uv")
        .args(["python", "find", "3.12"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        && output.status.success()
    {
        let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let path: PathBuf = PathBuf::from(raw);
        if path.is_file() {
            return path;
        }
    }
    if cfg!(windows)
        && let Ok(local_app_data) = std::env::var("LOCALAPPDATA")
    {
        let path: PathBuf = PathBuf::from(local_app_data)
            .join("Programs")
            .join("Python")
            .join("Python312")
            .join("python.exe");
        if path.is_file() {
            return path;
        }
    }
    panic!("CPython 3.12 is required for the generated pyc auto-route test")
}

#[allow(clippy::disallowed_methods)]
fn scratch(purpose: &str) -> disrobe_core::scratch::ScratchDir {
    disrobe_core::scratch::ScratchDir::create(purpose).expect("create scratch directory")
}

fn compile_source(interpreter: &Path, source: &Path, pyc: &Path) {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(source)
        .arg(pyc)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn CPython 3.12: {error}"));
    assert!(
        output.status.success(),
        "CPython 3.12 failed to compile the fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn terminal_decompile_source(out_dir: &Path) -> Option<String> {
    let entries: std::fs::ReadDir = std::fs::read_dir(out_dir).ok()?;
    entries
        .filter_map(Result::ok)
        .find_map(|entry: std::fs::DirEntry| {
            let name: String = entry.file_name().to_string_lossy().into_owned();
            let output: PathBuf = entry.path().join("output.bin");
            (name.contains("py-decompile") && entry.path().is_dir())
                .then(|| std::fs::read_to_string(output).ok())
                .flatten()
        })
}

#[test]
fn auto_routes_generated_pyc_and_preserves_guarded_try_loop() {
    let input_scratch: disrobe_core::scratch::ScratchDir = scratch("auto-python-loop-try-input");
    let source: PathBuf = input_scratch.path().join("guarded_read.py");
    let pyc: PathBuf = input_scratch.path().join("guarded_read.pyc");
    std::fs::write(&source, SOURCE).expect("write Python fixture source");
    compile_source(&python_312(), &source, &pyc);

    let out_scratch: disrobe_core::scratch::ScratchDir = scratch("auto-python-loop-try-output");
    let output: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&pyc)
        .arg("--out")
        .arg(out_scratch.path())
        .arg("--max-depth")
        .arg("3")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn disrobe auto: {error}"));
    assert!(
        output.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let chain_raw: String = std::fs::read_to_string(out_scratch.path().join("chain.json"))
        .expect("read auto chain.json");
    let chain: serde_json::Value = serde_json::from_str(&chain_raw).expect("parse auto chain.json");
    let passes: Vec<&str> = chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .expect("chain.json nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node.get("pass").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        passes.contains(&"py.decompile"),
        "auto must route the generated pyc through registered py.decompile; passes: {passes:?}"
    );

    let recovered: String = terminal_decompile_source(out_scratch.path())
        .expect("captured py.decompile output must contain recovered source");
    let expected: &str = r#"while active():
        if primary() or secondary():
            try:
                sink(read())
            except LookupError:
                sink(None)
            continue
        sink("ready")"#;
    assert!(
        recovered.contains(expected),
        "recovered source must preserve the exact guarded loop structure; source:\n{recovered}"
    );
    assert_eq!(recovered.matches("while active():").count(), 1);
    assert_eq!(recovered.matches("if primary() or secondary():").count(), 1);
    assert_eq!(recovered.matches("except LookupError:").count(), 1);
    assert_eq!(recovered.matches("continue").count(), 1);
}
