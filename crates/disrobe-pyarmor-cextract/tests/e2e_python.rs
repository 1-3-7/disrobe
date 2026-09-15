#![cfg(not(target_os = "windows"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_python() -> Option<PathBuf> {
    if let Some(env_value) = std::env::var_os("PYO3_PYTHON") {
        let p: PathBuf = PathBuf::from(env_value);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(out) = std::process::Command::new("uv")
        .args(["python", "find", "3.9"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        && out.status.success()
    {
        let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let p: PathBuf = PathBuf::from(raw);
        if p.is_file() {
            return Some(p);
        }
    }
    let candidates: [&str; 6] = [
        "/usr/bin/python3.14",
        "/usr/local/bin/python3.14",
        "/opt/homebrew/bin/python3.14",
        "/usr/bin/python3.12",
        "/usr/local/bin/python3.12",
        "/usr/bin/python3",
    ];
    for cand in candidates {
        let p: PathBuf = PathBuf::from(cand);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn cextract_importable(python: &Path) -> bool {
    let out: std::io::Result<Output> = Command::new(python)
        .arg("-c")
        .arg("import disrobe_cextract; print(disrobe_cextract.__version__)")
        .output();
    matches!(out, Ok(o) if o.status.success())
}

#[test]
fn synthetic_c_eval_intercept_captures_user_code() {
    let Some(python): Option<PathBuf> = workspace_python() else {
        eprintln!("SKIP: no python interpreter found");
        return;
    };
    if !cextract_importable(&python) {
        eprintln!(
            "SKIP: disrobe_cextract not importable from {} (run `maturin develop` against this interpreter first)",
            python.display()
        );
        return;
    }
    let script: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e_synthetic.py");
    assert!(script.exists(), "missing {}", script.display());
    let output: Output = Command::new(&python).arg(&script).output().expect("spawn");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "python {} {} failed (exit {:?})\nstdout: {stdout}\nstderr: {stderr}",
        python.display(),
        script.display(),
        output.status.code()
    );
    assert!(
        stdout.contains("OK: user-code captured via cextract"),
        "expected success marker; got:\n{stdout}"
    );
    let backend_modern: bool = stdout.contains("\"backend\": \"modern\"");
    let backend_legacy: bool = stdout.contains("\"backend\": \"legacy\"");
    assert!(
        backend_modern || backend_legacy,
        "backend should be modern or legacy; got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"matched_user_code\": true"),
        "user code object was not matched; got:\n{stdout}"
    );
}
