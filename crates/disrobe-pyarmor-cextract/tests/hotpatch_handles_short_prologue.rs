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
    let p: PathBuf = PathBuf::from("C:/Python314/python.exe");
    if p.exists() {
        return Some(p);
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
fn hotpatch_keeps_scanning_until_min_hook_bytes_reached() {
    let Some(python): Option<PathBuf> = workspace_python() else {
        eprintln!("SKIP: no python interpreter found");
        return;
    };
    if !cextract_importable(&python) {
        eprintln!("SKIP: disrobe_cextract not importable");
        return;
    }
    let script: &str = r#"
import json
import disrobe_cextract as cx
import os, tempfile, importlib.util
os.environ["DISROBE_CEXTRACT_BACKEND"] = "hotpatch"
out = tempfile.mkdtemp(prefix="disrobe_short_prologue_")
backend = cx.install_intercept(out, "short_prologue", importlib.util.MAGIC_NUMBER, None)
info = cx.backend_info()
print(json.dumps({"backend": backend, "saved_prologue_len": info.get("saved_prologue_len", 0)}))
assert backend == "hotpatch", f"expected hotpatch, got {backend}"
assert info.get("saved_prologue_len", 0) >= 14, "saved prologue must be at least 14 bytes"
cx.uninstall_intercept()
"#;
    let out: Output = Command::new(&python)
        .arg("-c")
        .arg(script)
        .output()
        .expect("spawn python");
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "short-prologue selection failed: stdout={stdout} stderr={stderr}"
    );
}
