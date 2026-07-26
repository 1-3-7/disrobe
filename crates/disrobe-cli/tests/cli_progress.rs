#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_path, write_bytes};
use disrobe_core::progress::{CapturingProgress, Progress, ProgressEvent};

#[test]
fn progress_trait_fires_under_simulated_pipeline() {
    let p: CapturingProgress = CapturingProgress::new();
    p.set_total(3);
    p.set_message("starting");
    for i in 0..3u64 {
        p.set_pos(i + 1);
        p.tick();
    }
    p.finish("done");
    let snap: Vec<ProgressEvent> = p.snapshot();
    assert!(
        !snap.is_empty(),
        "progress events MUST be recorded; got empty snapshot"
    );
    assert!(
        snap.len() >= 5,
        "expected at least set_total + set_message + 3 ticks; got {} events",
        snap.len()
    );
    assert_eq!(snap[0], ProgressEvent::SetTotal(3));
    let tick_count: usize = snap
        .iter()
        .filter(|e| matches!(e, ProgressEvent::Tick))
        .count();
    assert_eq!(tick_count, 3, "expected exactly 3 ticks");
}

#[test]
fn cli_accepts_progress_flag_without_crashing() {
    let src: PathBuf = temp_path("progress-cli", "py");
    write_bytes(&src, b"k = 9\n");
    let r: Run = run_disrobe(&["--progress", "always", "py", "deob", src.to_str().unwrap()]);
    assert_eq!(
        r.code, 0,
        "--progress always must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
}

fn has_control_codes(s: &str) -> bool {
    s.chars().any(|c: char| {
        let b: u32 = c as u32;
        b == 0x1b || b == 0x0d || (b < 0x20 && b != 0x0a && b != 0x09)
    })
}

fn auto_fixture() -> PathBuf {
    let src: PathBuf = temp_path("auto-progress", "py");
    write_bytes(
        &src,
        b"import os\n\n\ndef greet(name):\n    return f'hi {name}'\n\n\nprint(greet('world'))\n",
    );
    src
}

#[test]
fn auto_default_progress_emits_no_control_codes_when_piped() {
    let src: PathBuf = auto_fixture();
    let out_dir: PathBuf = temp_path("auto-out-default", "dir");
    let r: Run = run_disrobe(&[
        "auto",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "auto must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout),
        "piped stdout must carry zero ANSI/carriage-return control codes; got {:?}",
        r.stdout
    );
    assert!(
        !has_control_codes(&r.stderr),
        "piped stderr must carry zero ANSI/carriage-return control codes; got {:?}",
        r.stderr
    );
}

#[test]
fn auto_progress_always_stays_plain_on_a_non_tty() {
    let src: PathBuf = auto_fixture();
    let out_dir: PathBuf = temp_path("auto-out-always", "dir");
    let r: Run = run_disrobe(&[
        "--progress",
        "always",
        "auto",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "auto --progress always must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout),
        "even with --progress always, a non-tty stdout must stay plain; got {:?}",
        r.stdout
    );
    assert!(
        !has_control_codes(&r.stderr),
        "indicatif must draw nothing to a non-tty stderr even with --progress always; got {:?}",
        r.stderr
    );
}

#[test]
fn auto_quiet_suppresses_progress_and_keeps_streams_plain() {
    let src: PathBuf = auto_fixture();
    let out_dir: PathBuf = temp_path("auto-out-quiet", "dir");
    let r: Run = run_disrobe(&[
        "--quiet",
        "auto",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "auto --quiet must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout),
        "--quiet stdout must carry zero control codes; got {:?}",
        r.stdout
    );
    assert!(
        !has_control_codes(&r.stderr),
        "--quiet must force progress off, so stderr must carry zero control codes; got {:?}",
        r.stderr
    );
}

#[test]
fn native_unpack_progress_always_draws_nothing_on_a_non_tty() {
    let src: PathBuf = temp_path("native-unpack-progress", "bin");
    write_bytes(&src, b"not a packed executable, just plain bytes\n");
    let out_path: PathBuf = temp_path("native-unpack-out", "bin");
    let r: Run = run_disrobe(&[
        "--progress",
        "always",
        "native",
        "unpack",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(
        r.code, 0,
        "native unpack on a non-packer must fail. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout),
        "native unpack stdout must stay byte-clean even with --progress always; got {:?}",
        r.stdout
    );
    assert!(
        !has_control_codes(&r.stderr),
        "native unpack spinner must draw nothing to a non-tty stderr; got {:?}",
        r.stderr
    );
}

#[test]
fn native_unpack_quiet_suppresses_progress_on_a_non_tty() {
    let src: PathBuf = temp_path("native-unpack-quiet", "bin");
    write_bytes(&src, b"plain bytes with no packer signature\n");
    let out_path: PathBuf = temp_path("native-unpack-quiet-out", "bin");
    let r: Run = run_disrobe(&[
        "--quiet",
        "native",
        "unpack",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(
        r.code, 0,
        "native unpack on a non-packer must fail. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout) && !has_control_codes(&r.stderr),
        "native unpack --quiet must keep both streams control-code-free; stdout={:?} stderr={:?}",
        r.stdout,
        r.stderr
    );
}

#[test]
fn auto_json_output_is_clean_json_with_no_progress_bleed() {
    let src: PathBuf = auto_fixture();
    let out_dir: PathBuf = temp_path("auto-out-json", "dir");
    let r: Run = run_disrobe(&[
        "--json",
        "auto",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "auto --json must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout),
        "--json stdout must be pure machine output with zero control codes; got {:?}",
        r.stdout
    );
    let parsed: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&r.stdout);
    assert!(
        parsed.is_ok(),
        "--json stdout must parse as a single JSON document; got {:?}",
        r.stdout
    );
    assert!(
        !has_control_codes(&r.stderr),
        "--json must force progress off, so stderr must carry zero control codes; got {:?}",
        r.stderr
    );
}

fn locate_python() -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for name in ["python3", "python"] {
        for dir in std::env::split_paths(&path_var) {
            for variant in [name.to_owned(), format!("{name}.exe")] {
                let p: PathBuf = dir.join(&variant);
                if p.is_file() && interpreter_runs(&p) {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn interpreter_runs(candidate: &std::path::Path) -> bool {
    std::process::Command::new(candidate)
        .arg("-c")
        .arg("pass")
        .output()
        .is_ok_and(|out: std::process::Output| out.status.success())
}

fn compile_pyc(python: &std::path::Path, src: &std::path::Path, dst: &std::path::Path) -> bool {
    let src_str: String = src.to_string_lossy().replace('\\', "\\\\");
    let dst_str: String = dst.to_string_lossy().replace('\\', "\\\\");
    let script: String = format!(
        "import py_compile,sys\ntry:\n    py_compile.compile('{src_str}', cfile='{dst_str}', doraise=True)\nexcept Exception as e:\n    sys.stderr.write(str(e));sys.exit(2)\n"
    );
    std::process::Command::new(python)
        .args(["-c", &script])
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

#[test]
fn py_decompile_json_output_is_clean_with_no_progress_bleed() {
    let Some(python): Option<PathBuf> = locate_python() else {
        eprintln!("skipping py_decompile_json clean test: no python on PATH");
        return;
    };
    let dir: PathBuf = temp_path("py-dec-progress", "dir");
    std::fs::create_dir_all(&dir).unwrap();
    let py_path: PathBuf = dir.join("greet.py");
    let pyc_path: PathBuf = dir.join("greet.pyc");
    let out_dir: PathBuf = dir.join("recovered");
    write_bytes(&py_path, b"def greet(name):\n    return f'hi {name}'\n");
    if !compile_pyc(&python, &py_path, &pyc_path) {
        eprintln!("skipping py_decompile_json clean test: py_compile failed");
        return;
    }
    let r: Run = run_disrobe(&[
        "--json",
        "py",
        "decompile",
        pyc_path.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "py decompile --json must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout),
        "py decompile --json stdout must carry zero control codes; got {:?}",
        r.stdout
    );
    assert!(
        !has_control_codes(&r.stderr),
        "py decompile --json must force the spinner off, so stderr must be control-code-free; got {:?}",
        r.stderr
    );
}

#[test]
fn py_decompile_progress_always_stays_plain_on_a_non_tty() {
    let Some(python): Option<PathBuf> = locate_python() else {
        eprintln!("skipping py_decompile progress-always test: no python on PATH");
        return;
    };
    let dir: PathBuf = temp_path("py-dec-always", "dir");
    std::fs::create_dir_all(&dir).unwrap();
    let py_path: PathBuf = dir.join("greet.py");
    let pyc_path: PathBuf = dir.join("greet.pyc");
    let out_dir: PathBuf = dir.join("recovered");
    write_bytes(&py_path, b"def greet(name):\n    return f'hi {name}'\n");
    if !compile_pyc(&python, &py_path, &pyc_path) {
        eprintln!("skipping py_decompile progress-always test: py_compile failed");
        return;
    }
    let r: Run = run_disrobe(&[
        "--progress",
        "always",
        "py",
        "decompile",
        pyc_path.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "py decompile --progress always must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !has_control_codes(&r.stdout) && !has_control_codes(&r.stderr),
        "py decompile spinner must draw nothing to a non-tty even with --progress always; stdout={:?} stderr={:?}",
        r.stdout,
        r.stderr
    );
}
