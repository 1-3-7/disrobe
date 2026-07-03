#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn temp_dir(stem: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let p: PathBuf = std::env::temp_dir().join(format!("disrobe-pydec-{stem}-{pid}-{seq}"));
    let _: std::io::Result<()> = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

fn locate_python() -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for name in ["python3", "python"] {
        for dir in std::env::split_paths(&path_var) {
            for variant in [name.to_owned(), format!("{name}.exe")] {
                let p: PathBuf = dir.join(&variant);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn compile_py_to_pyc(python: &Path, src: &Path, dst: &Path) -> Result<(), String> {
    let src_str: String = src
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('\'', "\\'");
    let dst_str: String = dst
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('\'', "\\'");
    let script: String = format!(
        "import py_compile,sys\n\
try:\n    py_compile.compile('{src_str}', cfile='{dst_str}', doraise=True)\n\
except Exception as e:\n    sys.stderr.write(str(e));sys.exit(2)\n"
    );
    let out: std::process::Output = Command::new(python)
        .args(["-c", &script])
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "py_compile failed: code={:?} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn run_disrobe(args: &[String]) -> (i32, String, String) {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli` before tests",
        bin.display()
    );
    let out: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn assert_recompiles(python: &Path, source_path: &Path) {
    let probe: std::process::Output = Command::new(python)
        .args([
            "-c",
            &format!(
                "import py_compile,sys;py_compile.compile(r'{}',doraise=True);sys.exit(0)",
                source_path.display()
            ),
        ])
        .output()
        .expect("spawn python recompile check");
    assert!(
        probe.status.success(),
        "recovered source at {} did not recompile: stderr={}",
        source_path.display(),
        String::from_utf8_lossy(&probe.stderr)
    );
}

fn case(stem: &str, source: &str) {
    let Some(python): Option<PathBuf> = locate_python() else {
        eprintln!("skipping {stem}: no python on PATH");
        return;
    };
    let dir: PathBuf = temp_dir(stem);
    let py_path: PathBuf = dir.join(format!("{stem}.py"));
    let pyc_path: PathBuf = dir.join(format!("{stem}.pyc"));
    let out_dir: PathBuf = dir.join("recovered");
    std::fs::write(&py_path, source.as_bytes()).expect("write py fixture");
    if let Err(e) = compile_py_to_pyc(&python, &py_path, &pyc_path) {
        panic!("compile {stem}: {e}");
    }
    let args: Vec<String> = vec![
        "py".to_owned(),
        "decompile".to_owned(),
        pyc_path.to_string_lossy().into_owned(),
        "--out".to_owned(),
        out_dir.to_string_lossy().into_owned(),
        "--json".to_owned(),
    ];
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&args);
    assert_eq!(code, 0, "disrobe failed: stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("py decompile: OK"),
        "missing OK line. stdout={stdout}"
    );
    assert!(
        stdout.contains("backend:") && stdout.contains("native"),
        "expected native backend label, stdout={stdout}"
    );
    let recovered: PathBuf = out_dir.join(format!("{stem}.py"));
    assert!(
        recovered.exists(),
        "recovered source not at {}",
        recovered.display()
    );
    let body: String = std::fs::read_to_string(&recovered).expect("read recovered");
    assert!(!body.trim().is_empty(), "recovered file empty");
    assert_recompiles(&python, &recovered);
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest_body: String =
        std::fs::read_to_string(&manifest_path).expect("read manifest.json");
    assert!(
        manifest_body.contains("\"native\""),
        "manifest missing native backend: {manifest_body}"
    );
    assert!(
        manifest_body.contains("roundtrip"),
        "manifest missing roundtrip: {manifest_body}"
    );
}

#[test]
fn native_decompile_recovers_greet_function() {
    case("greet", "def greet(name):\n    return f\"hello, {name}\"\n");
}

#[test]
fn no_roundtrip_skips_interpreter_and_marks_skipped() {
    let Some(python): Option<PathBuf> = locate_python() else {
        eprintln!("skipping no_roundtrip: no python on PATH");
        return;
    };
    let dir: PathBuf = temp_dir("no_roundtrip");
    let py_path: PathBuf = dir.join("no_roundtrip.py");
    let pyc_path: PathBuf = dir.join("no_roundtrip.pyc");
    let out_dir: PathBuf = dir.join("recovered");
    std::fs::write(&py_path, b"def greet(name):\n    return f\"hi, {name}\"\n").expect("write py");
    if let Err(e) = compile_py_to_pyc(&python, &py_path, &pyc_path) {
        panic!("compile no_roundtrip: {e}");
    }
    let args: Vec<String> = vec![
        "py".to_owned(),
        "decompile".to_owned(),
        pyc_path.to_string_lossy().into_owned(),
        "--out".to_owned(),
        out_dir.to_string_lossy().into_owned(),
        "--no-roundtrip".to_owned(),
        "--json".to_owned(),
    ];
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&args);
    assert_eq!(code, 0, "disrobe failed: stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("py decompile: OK"),
        "missing OK line. stdout={stdout}"
    );
    let recovered: PathBuf = out_dir.join("no_roundtrip.py");
    assert!(
        recovered.exists(),
        "recovered source missing under --no-roundtrip"
    );
    let manifest_body: String =
        std::fs::read_to_string(out_dir.join("manifest.json")).expect("read manifest.json");
    assert!(
        manifest_body.contains("\"status\": \"skipped\""),
        "roundtrip not marked skipped: {manifest_body}"
    );
}

#[test]
fn native_decompile_recovers_arithmetic_module() {
    case(
        "math_ops",
        "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b\n",
    );
}

#[test]
fn native_decompile_recovers_simple_class() {
    case(
        "simple_class",
        "class Counter:\n    def __init__(self):\n        self.n = 0\n    def inc(self):\n        self.n += 1\n        return self.n\n",
    );
}
