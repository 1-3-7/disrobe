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
    let candidates: [&str; 3] = [
        "C:/Python314/python.exe",
        "C:/Users/-/AppData/Local/Programs/Python/Python314/python.exe",
        "C:/Users/-/AppData/Local/Programs/Python/Python312/python.exe",
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
fn hotpatch_revert_restores_original_eval_code() {
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
    let script: &str = r#"
import sys, json
import disrobe_cextract as cx
result = cx._hotpatch_selftest()
print(json.dumps(result))
assert result.get("post_uninstall_eval_works") is True, "post-uninstall PyEval_EvalCode regressed"
assert result.get("captured", 0) >= 1, "hotpatch backend did not capture the sentinel code object"
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
        "selftest failed: stdout={stdout} stderr={stderr}"
    );
}
