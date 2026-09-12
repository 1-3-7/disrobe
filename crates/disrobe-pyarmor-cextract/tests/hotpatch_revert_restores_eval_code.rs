#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

#[cfg(not(target_os = "windows"))]
use std::path::Path;
#[cfg(not(target_os = "windows"))]
use std::process::{Command, Output};

static CAPTURE_BUFFER_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(not(target_os = "windows"))]
fn workspace_python() -> Option<PathBuf> {
    if let Some(env_value) = std::env::var_os("PYO3_PYTHON") {
        let p: PathBuf = PathBuf::from(env_value);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(out) = std::process::Command::new("uv")
        .args(["python", "find", "3.14"])
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
    let candidates: [&str; 3] = [
        "/usr/bin/python3.14",
        "/usr/local/bin/python3.14",
        "/opt/homebrew/bin/python3.14",
    ];
    for cand in candidates {
        let p: PathBuf = PathBuf::from(cand);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn cextract_importable(python: &Path) -> bool {
    let out: std::io::Result<Output> = Command::new(python)
        .arg("-c")
        .arg("import disrobe_cextract; print(disrobe_cextract.__version__)")
        .output();
    matches!(out, Ok(o) if o.status.success())
}

#[test]
fn capture_buffer_owns_scratch_through_reconfigure_and_release() {
    let _guard: MutexGuard<'_, ()> = CAPTURE_BUFFER_TEST_LOCK
        .lock()
        .expect("lock capture buffer test");
    let first: PathBuf = disrobe_cextract::test_support::reconfigure_with_new_scratch()
        .expect("configure first scratch directory");
    assert!(first.is_dir(), "configured scratch directory disappeared");

    let second: PathBuf = disrobe_cextract::test_support::reconfigure_with_new_scratch()
        .expect("configure replacement scratch directory");
    assert_ne!(first, second, "scratch directory names collided");
    assert!(
        !first.exists(),
        "reconfigure retained the previous scratch directory"
    );
    assert!(second.is_dir(), "replacement scratch directory disappeared");

    disrobe_cextract::test_support::release_scratch()
        .expect("release scratch directory at uninstall boundary");
    assert!(!second.exists(), "uninstall retained the scratch directory");
}

#[test]
fn capture_buffer_surfaces_deleted_and_unusable_scratch_errors() {
    let _guard: MutexGuard<'_, ()> = CAPTURE_BUFFER_TEST_LOCK
        .lock()
        .expect("lock capture buffer test");
    let deleted_error: String = disrobe_cextract::test_support::scratch_write_failure(false)
        .expect("capture error after external deletion");
    assert!(
        deleted_error.starts_with("CEXT-0006:"),
        "unexpected deleted-directory error: {deleted_error}"
    );

    let unusable_error: String = disrobe_cextract::test_support::scratch_write_failure(true)
        .expect("capture error after directory became unusable");
    assert!(
        unusable_error.starts_with("CEXT-0006:"),
        "unexpected unusable-directory error: {unusable_error}"
    );
}

#[cfg(not(target_os = "windows"))]
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
assert result.get("scratch_released") is True, "hotpatch scratch directory survived uninstall"
for make_unusable in (False, True):
    failure = cx._hotpatch_scratch_failure_selftest(make_unusable)
    assert failure.get("error_is_os_error") is True, failure
    assert failure.get("scratch_released") is True, failure
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
