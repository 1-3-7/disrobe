#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::doc_markdown
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::{band_scratch, find_interpreter};
use common::stdlib_measure::{find_disrobe, workspace_target};

const SOURCE: &str = r"def consume(next_item, sink):
    while True:
        try:
            item = next_item()
            if item is None:
                break
            sink(item)
        finally:
            sink('cleanup')
    sink('done')
";

const DRIVER: &str = r"def values(items):
    iterator = iter(items)
    return lambda: next(iterator)

events = []
consume(values(['one', None]), events.append)
print(events)
";

fn compile_to_pyc(interpreter: &Path, source: &Path, pyc: &Path) {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(source)
        .arg(pyc)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn {}: {error}", interpreter.display()));
    assert!(
        output.status.success(),
        "{} failed to compile the fixture: {}",
        interpreter.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn execute(interpreter: &Path, program: &Path) -> String {
    let output: std::process::Output = Command::new(interpreter)
        .arg(program)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn {}: {error}", interpreter.display()));
    assert!(
        output.status.success(),
        "{} rejected {}: {}",
        interpreter.display(),
        program.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("runtime output must be UTF-8")
}

fn captured_decompile_source(out_dir: &Path) -> PathBuf {
    let mut stages: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", out_dir.display()))
        .filter_map(Result::ok)
        .map(|entry: std::fs::DirEntry| entry.path())
        .filter(|path: &PathBuf| {
            path.is_dir()
                && path.file_name().is_some_and(|name: &std::ffi::OsStr| {
                    name.to_string_lossy().contains("py-decompile")
                })
        })
        .collect();
    stages.sort();
    stages
        .into_iter()
        .map(|stage: PathBuf| stage.join("output.bin"))
        .find(|output: &PathBuf| output.is_file())
        .unwrap_or_else(|| {
            panic!(
                "no captured py.decompile output under {}",
                out_dir.display()
            )
        })
}

fn chain_passes(chain: &serde_json::Value) -> Vec<String> {
    chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes: &Vec<serde_json::Value>| {
            nodes
                .iter()
                .filter_map(|node: &serde_json::Value| {
                    node.get("pass")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn auto_preserves_infinite_try_finally_break_body_and_tail() {
    let interpreter: PathBuf = find_interpreter("3.12").unwrap_or_else(|| {
        panic!("CPython 3.12 is required for the infinite-loop try/finally fixture")
    });
    let disrobe: PathBuf = find_disrobe().unwrap_or_else(|| {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it before this caller test",
            workspace_target().display()
        )
    });
    let scratch: PathBuf = band_scratch("infinite-loop-try-finally-auto");
    let source_path: PathBuf = scratch.join("fixture.py");
    let pyc_path: PathBuf = scratch.join("fixture.pyc");
    let original_path: PathBuf = scratch.join("original.py");
    let recovered_path: PathBuf = scratch.join("recovered.py");
    let out_dir: PathBuf = scratch.join("out");
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::write(&source_path, SOURCE).expect("write fixture source");
    compile_to_pyc(&interpreter, &source_path, &pyc_path);

    let output: std::process::Output = Command::new(&disrobe)
        .arg("auto")
        .arg(&pyc_path)
        .arg("--out")
        .arg(&out_dir)
        .arg("--max-depth")
        .arg("3")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe auto: {error}"));
    assert!(
        output.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let chain_raw: String =
        std::fs::read_to_string(out_dir.join("chain.json")).expect("read auto chain.json");
    let chain: serde_json::Value = serde_json::from_str(&chain_raw).expect("parse auto chain.json");
    let passes: Vec<String> = chain_passes(&chain);
    assert!(
        passes.iter().any(|pass: &String| pass == "py.decompile"),
        "auto did not reach py.decompile: {passes:?}"
    );

    let recovered_source_path: PathBuf = captured_decompile_source(&out_dir);
    let recovered: String =
        std::fs::read_to_string(&recovered_source_path).expect("read recovered source");
    assert_eq!(recovered.matches("while True:").count(), 1, "{recovered}");
    assert_eq!(recovered.matches("try:").count(), 1, "{recovered}");
    assert_eq!(recovered.matches("finally:").count(), 1, "{recovered}");
    assert_eq!(
        recovered.matches("if item is None:").count(),
        1,
        "{recovered}"
    );
    assert_eq!(recovered.matches("break").count(), 1, "{recovered}");
    assert_eq!(recovered.matches("sink(item)").count(), 1, "{recovered}");
    assert_eq!(
        recovered.matches("sink(\"cleanup\")").count(),
        1,
        "{recovered}"
    );
    assert_eq!(
        recovered.matches("sink(\"done\")").count(),
        1,
        "{recovered}"
    );

    let original_program: String = format!("{SOURCE}\n{DRIVER}");
    let recovered_program: String = format!("{recovered}\n{DRIVER}");
    std::fs::write(&original_path, original_program).expect("write original program");
    std::fs::write(&recovered_path, recovered_program).expect("write recovered program");
    let original_output: String = execute(&interpreter, &original_path);
    let recovered_output: String = execute(&interpreter, &recovered_path);
    assert_eq!(recovered_output, original_output);
    assert_eq!(
        original_output.trim(),
        "['one', 'cleanup', 'cleanup', 'done']"
    );
}
