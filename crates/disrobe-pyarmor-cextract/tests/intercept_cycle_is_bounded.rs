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
    for version in ["3.14", "3.12", "3.9"] {
        if let Ok(out) = Command::new("uv")
            .args(["python", "find", version])
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
    }
    let candidates: [&str; 4] = [
        "/usr/bin/python3.14",
        "/usr/local/bin/python3.14",
        "/usr/bin/python3.12",
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
fn repeated_install_uninstall_does_not_leak_or_retain_state() {
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
import disrobe_cextract as cx
import importlib.util, json, tempfile

mn = importlib.util.MAGIC_NUMBER
cycles = 2000
for i in range(cycles):
    out = tempfile.mkdtemp(prefix="disrobe_cycle_")
    cx.install_intercept(out, "cycle_stem", mn, None)
    assert cx.captured_count() == 0, f"cycle {i}: buffer state not reset to 0"
    cx.uninstall_intercept()
print(json.dumps({"cycles": cycles, "ok": True}))
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
        "install/uninstall cycle loop failed: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("\"ok\": true"),
        "expected bounded-cycle success marker; got:\n{stdout}"
    );
}
