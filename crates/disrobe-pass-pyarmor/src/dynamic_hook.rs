use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use disrobe_core::scratch::ScratchFile;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::{MAX_JSON_FILE_BYTES, read_file_bounded};

const HELPER_SCRIPT: &str = include_str!("v6v7_dynamic_hook.py");
const HELPER_SCRATCH_PURPOSE: &str = "v6v7_dynamic_hook";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const PROBE_TIMEOUT_SECS: u64 = 10;
const MIN_PYTHON: (u8, u8, u8) = (3, 9, 7);
const MAX_DYNAMIC_CAPTURE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureSource {
    Monkeypatch,
    AuditHook,
    Exec,
    Compile,
    Trace,
    GcWalk,
    Pytrace,
    Cextract,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureManifestEntry {
    pub index: usize,
    pub size: usize,
    pub sha256: String,
    pub pyc_path: String,
    #[serde(default)]
    pub co_filename: String,
    #[serde(default)]
    pub co_name: String,
    #[serde(default)]
    pub co_names_count: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureLimitation {
    pub id: String,
    pub channel: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureManifest {
    pub schema: String,
    pub wrapper: String,
    pub subprocess_python: Vec<u32>,
    pub magic_number_hex: String,
    pub captures: CaptureGroups,
    #[serde(default)]
    pub exceptions: Vec<serde_json::Value>,
    #[serde(default)]
    pub limitations: Vec<CaptureLimitation>,
    pub primary: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureGroups {
    #[serde(default)]
    pub monkeypatch: Vec<CaptureManifestEntry>,
    #[serde(default)]
    pub audithook: Vec<CaptureManifestEntry>,
    #[serde(default, rename = "exec")]
    pub exec_calls: Vec<CaptureManifestEntry>,
    #[serde(default, rename = "compile")]
    pub compile_calls: Vec<CaptureManifestEntry>,
    #[serde(default, rename = "trace")]
    pub trace_calls: Vec<CaptureManifestEntry>,
    #[serde(default, rename = "gcwalk")]
    pub gcwalk: Vec<CaptureManifestEntry>,
    #[serde(default, rename = "pytrace")]
    pub pytrace: Vec<CaptureManifestEntry>,
    #[serde(default, rename = "cextract")]
    pub cextract: Vec<CaptureManifestEntry>,
}

#[derive(Debug, Clone)]
pub struct InterpreterSpec {
    pub exe: PathBuf,
    pub version_args: Vec<String>,
}

impl InterpreterSpec {
    fn display_label(&self) -> String {
        if self.version_args.is_empty() {
            self.exe.display().to_string()
        } else {
            format!("{} {}", self.exe.display(), self.version_args.join(" "))
        }
    }
}

#[derive(Debug, Clone)]
pub struct DynamicHookResult {
    pub interpreter: PathBuf,
    pub interpreter_label: String,
    pub interpreter_version: (u8, u8, u8),
    pub manifest_path: PathBuf,
    pub manifest: CaptureManifest,
    pub stderr_excerpt: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicHookOptions {
    pub allow_dynamic: bool,
    pub timeout: Duration,
    pub disable_pytrace: bool,
    pub disable_cextract: bool,
}

impl Default for DynamicHookOptions {
    fn default() -> Self {
        Self {
            allow_dynamic: false,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            disable_pytrace: false,
            disable_cextract: false,
        }
    }
}

pub fn run_dynamic_hook(
    wrapper: &Path,
    out_dir: &Path,
    options: DynamicHookOptions,
) -> Result<DynamicHookResult> {
    run_dynamic_hook_with_target(wrapper, out_dir, options, None)
}

pub fn run_dynamic_hook_with_target(
    wrapper: &Path,
    out_dir: &Path,
    options: DynamicHookOptions,
    target: Option<(u8, u8)>,
) -> Result<DynamicHookResult> {
    if !options.allow_dynamic {
        return Err(Error::DynamicHookRequiresAllow);
    }

    std::fs::create_dir_all(out_dir)?;

    let spec: InterpreterSpec = locate_python(target)?;
    let version: (u8, u8, u8) = python_version(&spec)?;
    if !version_meets(version, MIN_PYTHON) {
        return Err(Error::DynamicHookPythonTooOld {
            found: format!("{}.{}.{}", version.0, version.1, version.2),
            required: format!("{}.{}.{}", MIN_PYTHON.0, MIN_PYTHON.1, MIN_PYTHON.2),
        });
    }

    let (helper_guard, mut helper_handle): (ScratchFile, std::fs::File) =
        ScratchFile::create(HELPER_SCRATCH_PURPOSE, "py")?;
    helper_handle.write_all(HELPER_SCRIPT.as_bytes())?;
    helper_handle.flush()?;
    drop(helper_handle);
    let helper_abs: PathBuf = helper_guard
        .path()
        .canonicalize()
        .unwrap_or_else(|_| helper_guard.path().to_path_buf());

    tracing::warn!(
        "--allow-dynamic executes the obfuscated PyArmor wrapper in a subprocess to capture marshal streams; only enable on trusted samples or sandbox externally"
    );

    let wrapper_abs: PathBuf = wrapper.canonicalize()?;
    let out_abs: PathBuf = out_dir.canonicalize()?;

    let mut cmd: Command = Command::new(&spec.exe);
    for arg in &spec.version_args {
        cmd.arg(arg);
    }
    cmd.arg(&helper_abs)
        .arg(&wrapper_abs)
        .arg(&out_abs)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env(
            "DISROBE_DISABLE_PYTRACE",
            if options.disable_pytrace { "1" } else { "0" },
        )
        .env(
            "DISROBE_DISABLE_CEXTRACT",
            if options.disable_cextract { "1" } else { "0" },
        )
        .current_dir(&out_abs);

    let child: std::process::Child = cmd.spawn().map_err(|e| {
        Error::KeyExtraction(format!("failed to spawn dynamic hook interpreter: {e}"))
    })?;
    let Some(captured): Option<disrobe_core::subprocess::CapturedOutput> =
        disrobe_core::subprocess::wait_with_output_timeout(
            child,
            options.timeout,
            MAX_DYNAMIC_CAPTURE,
        )
    else {
        return Err(Error::DynamicHookTimedOut {
            secs: options.timeout.as_secs(),
        });
    };
    let stderr_excerpt: String = String::from_utf8_lossy(&captured.stderr).into_owned();
    let exit_code: Option<i32> = captured.exit_code;

    let manifest_path: PathBuf = out_abs.join("manifest.json");
    let manifest_bytes: Vec<u8> = read_file_bounded(&manifest_path, MAX_JSON_FILE_BYTES)
        .map_err(|e: Error| dynamic_hook_manifest_read_error(exit_code, &stderr_excerpt, e))?;
    let manifest: CaptureManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::KeyExtraction(format!("failed to parse dynamic hook manifest: {e}")))?;

    if manifest.captures.monkeypatch.is_empty()
        && manifest.captures.audithook.is_empty()
        && manifest.captures.exec_calls.is_empty()
        && manifest.captures.compile_calls.is_empty()
        && manifest.captures.trace_calls.is_empty()
        && manifest.captures.gcwalk.is_empty()
        && manifest.captures.pytrace.is_empty()
        && manifest.captures.cextract.is_empty()
    {
        return Err(Error::DynamicHookZeroCaptures {
            stderr: stderr_excerpt,
        });
    }

    let interpreter_label: String = spec.display_label();
    Ok(DynamicHookResult {
        interpreter: spec.exe,
        interpreter_label,
        interpreter_version: version,
        manifest_path,
        manifest,
        stderr_excerpt,
        exit_code,
    })
}

fn locate_python(target: Option<(u8, u8)>) -> Result<InterpreterSpec> {
    let mut version_order: Vec<(u8, u8)> = target.map_or_else(
        || vec![(3, 9), (3, 10), (3, 11), (3, 12), (3, 13), (3, 14)],
        |t| {
            let mut chain: Vec<(u8, u8)> = vec![t];
            for minor in (9..=14u8).rev() {
                let v: (u8, u8) = (3, minor);
                if v != t {
                    chain.push(v);
                }
            }
            chain
        },
    );
    version_order.dedup();

    let mut searched: Vec<String> = Vec::new();
    for (maj, min) in &version_order {
        let py_flag: String = format!("-{maj}.{min}");
        let candidate: InterpreterSpec = InterpreterSpec {
            exe: PathBuf::from("py"),
            version_args: vec![py_flag.clone()],
        };
        if probe(&candidate, &mut searched) {
            return Ok(candidate);
        }
        let candidate2: InterpreterSpec = InterpreterSpec {
            exe: PathBuf::from(format!("python{maj}.{min}")),
            version_args: Vec::new(),
        };
        if probe(&candidate2, &mut searched) {
            return Ok(candidate2);
        }
    }
    let fallback_chain: [InterpreterSpec; 2] = [
        InterpreterSpec {
            exe: PathBuf::from("python3"),
            version_args: Vec::new(),
        },
        InterpreterSpec {
            exe: PathBuf::from("python"),
            version_args: Vec::new(),
        },
    ];
    for spec in fallback_chain {
        if probe(&spec, &mut searched) {
            return Ok(spec);
        }
    }
    Err(Error::DynamicHookNoPython { searched })
}

fn probe(spec: &InterpreterSpec, searched: &mut Vec<String>) -> bool {
    let label: String = spec.display_label();
    searched.push(label);
    let mut cmd: Command = Command::new(&spec.exe);
    for arg in &spec.version_args {
        cmd.arg(arg);
    }
    cmd.arg("-c").arg("print(0)");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_probe_capped(&mut cmd, Duration::from_secs(PROBE_TIMEOUT_SECS))
        .is_some_and(|(success, _stdout, _stderr): (bool, Vec<u8>, Vec<u8>)| success)
}

fn python_version(spec: &InterpreterSpec) -> Result<(u8, u8, u8)> {
    let mut cmd: Command = Command::new(&spec.exe);
    for arg in &spec.version_args {
        cmd.arg(arg);
    }
    cmd.arg("-c").arg(
        "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}')",
    );
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (success, stdout, _stderr): (bool, Vec<u8>, Vec<u8>) =
        run_probe_capped(&mut cmd, Duration::from_secs(PROBE_TIMEOUT_SECS)).ok_or_else(|| {
            Error::KeyExtraction(format!(
                "python version probe timed out after {PROBE_TIMEOUT_SECS}s"
            ))
        })?;
    if !success {
        return Err(Error::KeyExtraction(
            "could not query python version".to_owned(),
        ));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&stdout);
    parse_version(text.trim())
        .ok_or_else(|| Error::KeyExtraction(format!("could not parse python version: {text:?}")))
}

fn run_probe_capped(cmd: &mut Command, timeout: Duration) -> Option<(bool, Vec<u8>, Vec<u8>)> {
    let child: std::process::Child = cmd.spawn().ok()?;
    let captured: disrobe_core::subprocess::CapturedOutput =
        disrobe_core::subprocess::wait_with_output_timeout(child, timeout, MAX_DYNAMIC_CAPTURE)?;
    Some((
        captured.exit_code == Some(0),
        captured.stdout,
        captured.stderr,
    ))
}

fn parse_version(s: &str) -> Option<(u8, u8, u8)> {
    let mut parts: std::str::Split<'_, char> = s.split('.');
    let major: u8 = parts.next()?.parse().ok()?;
    let minor: u8 = parts.next()?.parse().ok()?;
    let patch: u8 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

const fn version_meets(found: (u8, u8, u8), required: (u8, u8, u8)) -> bool {
    if found.0 != required.0 {
        return found.0 > required.0;
    }
    if found.1 != required.1 {
        return found.1 > required.1;
    }
    found.2 >= required.2
}

fn dynamic_hook_manifest_read_error(
    exit_code: Option<i32>,
    stderr_excerpt: &str,
    source: Error,
) -> Error {
    let manifest_reason: String = format!("manifest read failed: {source}");
    let stderr: String = if stderr_excerpt.is_empty() {
        manifest_reason
    } else {
        format!("{stderr_excerpt}\n{manifest_reason}")
    };
    Error::DynamicHookSubprocess { exit_code, stderr }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn mock_bin_path() -> PathBuf {
        static RESOLVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_disrobe-pass-pyarmor-mock-proc") {
            let p_buf: PathBuf = PathBuf::from(p);
            if p_buf.is_file() {
                return p_buf;
            }
        }
        let _resolve_guard: std::sync::MutexGuard<'_, ()> = RESOLVE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exe_name: &str = if cfg!(windows) {
            "disrobe-pass-pyarmor-mock-proc.exe"
        } else {
            "disrobe-pass-pyarmor-mock-proc"
        };
        let target_dir: PathBuf = std::env::current_exe()
            .ok()
            .and_then(|p: PathBuf| {
                p.parent()
                    .and_then(|d: &Path| d.parent())
                    .map(Path::to_path_buf)
            })
            .unwrap_or_else(|| PathBuf::from("target/debug"));
        let candidate: PathBuf = target_dir.join(exe_name);
        if candidate.is_file() {
            return candidate;
        }
        let alt: PathBuf = target_dir.join("deps").join(exe_name);
        if alt.is_file() {
            return alt;
        }
        let status: std::process::ExitStatus = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "disrobe-pass-pyarmor",
                "--bin",
                "disrobe-pass-pyarmor-mock-proc",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn cargo build for mock-proc");
        assert!(status.success(), "cargo build mock-proc failed");
        assert!(candidate.is_file(), "mock-proc binary not at expected path");
        candidate
    }

    fn mock_cmd(args: &[&str]) -> Command {
        let mut cmd: Command = Command::new(mock_bin_path());
        cmd.args(args);
        cmd
    }

    #[test]
    fn probe_capped_timeout_actually_kills_a_sleeping_child() {
        let mut cmd: Command = mock_cmd(&["sleep", "5"]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start: Instant = Instant::now();
        let result: Option<(bool, Vec<u8>, Vec<u8>)> =
            run_probe_capped(&mut cmd, Duration::from_millis(300));
        let elapsed: Duration = start.elapsed();
        eprintln!(
            "[evidence] pyarmor timeout test: elapsed={elapsed:?} deadline=300ms sleep_requested=5s killed={}",
            result.is_none()
        );
        assert!(
            result.is_none(),
            "child sleeping 5s must be killed, not exit cleanly"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "wait must return near the 300ms deadline, not the 5s sleep; took {elapsed:?}"
        );
    }

    #[test]
    fn probe_capped_output_cap_truncates_a_flooding_child() {
        let flood_bytes: usize = MAX_DYNAMIC_CAPTURE * 2;
        let mut cmd: Command = mock_cmd(&["flood", &flood_bytes.to_string()]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (success, stdout, _stderr): (bool, Vec<u8>, Vec<u8>) =
            run_probe_capped(&mut cmd, Duration::from_secs(20))
                .expect("flood child must complete within timeout");
        assert!(success);
        eprintln!(
            "[evidence] pyarmor cap test: child_wrote={flood_bytes} captured={} cap={MAX_DYNAMIC_CAPTURE}",
            stdout.len()
        );
        assert_eq!(
            stdout.len(),
            MAX_DYNAMIC_CAPTURE,
            "captured stdout must be truncated to the cap, not the full {flood_bytes} bytes written"
        );
    }

    #[test]
    fn probe_capped_metacharacter_argv_passes_through_literally() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("pyarmor-metachar").expect("scratch dir");
        let weird_name: &str = "disrobe-metachar-'; & $HOME `id` (test) !bang %VAR% done.txt";
        let weird_path: PathBuf = scratch.path().join(weird_name);
        std::fs::write(&weird_path, b"payload").expect("write metachar file");

        let mut cmd: Command = mock_cmd(&["echo-args", &weird_path.to_string_lossy()]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (success, stdout, _stderr): (bool, Vec<u8>, Vec<u8>) =
            run_probe_capped(&mut cmd, Duration::from_secs(5))
                .expect("echo-args child must complete");
        assert!(success);
        let reported: String = String::from_utf8_lossy(&stdout).trim_end().to_owned();
        eprintln!(
            "[evidence] pyarmor metachar test: sent={:?} received={reported:?}",
            weird_path.to_string_lossy()
        );
        assert_eq!(
            reported,
            weird_path.to_string_lossy(),
            "the child must receive the metacharacter-laden path as a single literal argv element"
        );
    }

    fn helper_scratch_leftovers() -> Vec<PathBuf> {
        let prefix: String = format!("{HELPER_SCRATCH_PURPOSE}-{}-", std::process::id());
        let Ok(entries): std::io::Result<std::fs::ReadDir> =
            std::fs::read_dir(disrobe_core::scratch::scratch_root())
        else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry: std::fs::DirEntry| entry.path())
            .filter(|path: &PathBuf| {
                path.file_name()
                    .and_then(|name: &std::ffi::OsStr| name.to_str())
                    .is_some_and(|name: &str| name.starts_with(&prefix))
            })
            .collect()
    }

    fn directory_names(dir: &Path) -> Vec<String> {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|entry: std::fs::DirEntry| entry.file_name().to_str().map(str::to_owned))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_dynamic_hook_that_fails_leaves_the_output_directory_holding_only_the_operators_output() {
        let operator_workspace: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("pyarmor-hook-operator")
                .expect("scratch dir");
        let out_dir: PathBuf = operator_workspace.path().join("recovered");
        std::fs::create_dir_all(&out_dir).expect("mkdir out dir");
        let absent_wrapper: PathBuf = out_dir.join("no_such_wrapper.py");
        let options: DynamicHookOptions = DynamicHookOptions {
            allow_dynamic: true,
            timeout: Duration::from_secs(5),
            disable_pytrace: true,
            disable_cextract: true,
        };

        let error: Error = run_dynamic_hook_with_target(&absent_wrapper, &out_dir, options, None)
            .expect_err("a wrapper that does not exist cannot be canonicalized");
        if matches!(
            error,
            Error::DynamicHookNoPython { .. } | Error::DynamicHookPythonTooOld { .. }
        ) {
            eprintln!(
                "[skip] no python 3.9.7 or newer on PATH, so the helper is never written here"
            );
            return;
        }
        assert!(
            matches!(error, Error::Io(_)),
            "the missing wrapper must fail after the helper exists, got: {error:?}"
        );

        let remaining: Vec<String> = directory_names(&out_dir);
        let leftovers: Vec<PathBuf> = helper_scratch_leftovers();
        assert!(
            remaining.is_empty(),
            "the output directory must hold only what the operator asked for, found: {remaining:?}"
        );
        assert!(
            leftovers.is_empty(),
            "the guard must remove the helper when the run fails, found: {leftovers:?}"
        );
    }

    #[test]
    fn successful_hotpatch_session_is_uninstalled_and_drained() {
        let spec: InterpreterSpec =
            locate_python(Some((3, 12))).expect("Python 3.12 is required for the hotpatch gate");
        let version: (u8, u8, u8) = python_version(&spec).expect("query Python version");
        assert_eq!(
            (version.0, version.1),
            (3, 12),
            "the hotpatch gate requires Python 3.12, got {version:?} from {}",
            spec.display_label()
        );

        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("pyarmor-hotpatch-lifecycle")
                .expect("create scratch dir");
        let root: &Path = scratch.path();
        let helper_path: PathBuf = root.join("v6v7_dynamic_hook.py");
        let wrapper_path: PathBuf = root.join("wrapper.py");
        let shim_path: PathBuf = root.join("disrobe_cextract.py");
        let out_dir: PathBuf = root.join("out");
        let marker_path: PathBuf = root.join("cextract-order.txt");
        let shim: &str = r#"import marshal
import os
import pathlib

__limitation__ = "hotpatch lifecycle test shim"
capture_entry = None

def install_intercept(out_dir, wrapper_stem, magic_number, prefer):
    global capture_entry
    destination = pathlib.Path(out_dir) / f"{wrapper_stem}.hotpatch.pyc"
    body = marshal.dumps(compile("hotpatch_value = 42\n", "<hotpatch-shim>", "exec"))
    destination.write_bytes(bytes(magic_number[:4]) + b"\x00" * 12 + body)
    capture_entry = {
        "pyc_path": str(destination),
        "size": destination.stat().st_size,
        "blake3": "protocol-shim",
    }
    return "hotpatch"

def uninstall_intercept():
    marker = pathlib.Path(os.environ["DISROBE_CEXTRACT_ORDER_MARKER"])
    marker.write_text("uninstall\n", encoding="utf-8")
    return 1

def drain_into_manifest():
    marker = pathlib.Path(os.environ["DISROBE_CEXTRACT_ORDER_MARKER"])
    if not marker.is_file() or marker.read_text(encoding="utf-8") != "uninstall\n":
        raise RuntimeError("drain called before uninstall")
    marker.write_text("uninstall\ndrain\n", encoding="utf-8")
    return [capture_entry]
"#;
        std::fs::write(&helper_path, HELPER_SCRIPT).expect("write dynamic-hook helper");
        std::fs::write(&wrapper_path, "wrapper_value = 7\n").expect("write benign wrapper");
        std::fs::write(&shim_path, shim).expect("write cextract protocol shim");

        let mut command: Command = Command::new(&spec.exe);
        command.args(&spec.version_args);
        command
            .arg(&helper_path)
            .arg(&wrapper_path)
            .arg(&out_dir)
            .current_dir(root)
            .env("PYTHONPATH", root)
            .env("PYTHONIOENCODING", "utf-8")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("DISROBE_DISABLE_PYTRACE", "1")
            .env("DISROBE_DISABLE_CEXTRACT", "0")
            .env("DISROBE_CEXTRACT_ORDER_MARKER", &marker_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (success, stdout, stderr): (bool, Vec<u8>, Vec<u8>) =
            run_probe_capped(&mut command, Duration::from_secs(30))
                .expect("hotpatch helper must complete within the watchdog");
        let stdout_text: String = String::from_utf8_lossy(&stdout).into_owned();
        let stderr_text: String = String::from_utf8_lossy(&stderr).into_owned();
        assert!(
            success,
            "hotpatch helper failed under Python {version:?}: stdout:\n{stdout_text}\nstderr:\n{stderr_text}"
        );

        let order: String = std::fs::read_to_string(&marker_path).unwrap_or_else(|error| {
            panic!(
                "successful hotpatch session did not run teardown and drain in order: {error}; stdout:\n{stdout_text}\nstderr:\n{stderr_text}"
            )
        });
        assert_eq!(order, "uninstall\ndrain\n");
        let manifest_bytes: Vec<u8> =
            std::fs::read(out_dir.join("manifest.json")).expect("read helper manifest");
        let manifest: CaptureManifest =
            serde_json::from_slice(&manifest_bytes).expect("parse helper manifest");
        assert_eq!(manifest.primary.as_deref(), Some("cextract"));
        assert_eq!(manifest.captures.cextract.len(), 1);
        assert_eq!(
            manifest.captures.cextract[0].pyc_path,
            out_dir
                .join("cextract")
                .join("wrapper.hotpatch.pyc")
                .display()
                .to_string()
        );
        let limitation: &CaptureLimitation = manifest
            .limitations
            .iter()
            .find(|entry: &&CaptureLimitation| entry.id == "v6v7-c-eval-gap-cextract")
            .expect("cextract limitation entry");
        assert_eq!(limitation.channel, "cextract:hotpatch");
        assert_eq!(limitation.severity, "active");
        assert!(manifest.exceptions.iter().all(|entry: &serde_json::Value| {
            entry.get("phase").and_then(serde_json::Value::as_str) != Some("cextract-drain")
        }));
    }

    #[test]
    fn parse_version_handles_three_parts() {
        assert_eq!(parse_version("3.12.5"), Some((3, 12, 5)));
        assert_eq!(parse_version("3.9.0"), Some((3, 9, 0)));
        assert_eq!(parse_version("3.13"), Some((3, 13, 0)));
    }

    #[test]
    fn version_meets_basic() {
        assert!(version_meets((3, 9, 7), (3, 9, 7)));
        assert!(version_meets((3, 10, 0), (3, 9, 7)));
        assert!(!version_meets((3, 9, 6), (3, 9, 7)));
        assert!(!version_meets((2, 7, 18), (3, 9, 7)));
    }

    #[test]
    fn capture_source_round_trip_serde_cextract_variant() {
        let s: String = serde_json::to_string(&CaptureSource::Cextract).expect("serialize");
        assert_eq!(s, "\"Cextract\"");
        let back: CaptureSource = serde_json::from_str(&s).expect("deserialize");
        assert!(matches!(back, CaptureSource::Cextract));
    }

    #[test]
    fn capture_source_round_trip_serde_pytrace_variant() {
        let s: String = serde_json::to_string(&CaptureSource::Pytrace).expect("serialize");
        assert_eq!(s, "\"Pytrace\"");
        let back: CaptureSource = serde_json::from_str(&s).expect("deserialize");
        assert!(matches!(back, CaptureSource::Pytrace));
    }

    #[test]
    fn dynamic_hook_manifest_read_error_preserves_stderr_and_reason() {
        let source: Error = Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing manifest",
        ));
        let err: Error = dynamic_hook_manifest_read_error(Some(17), "child stderr", source);
        let Error::DynamicHookSubprocess { exit_code, stderr } = err else {
            panic!("expected subprocess error");
        };
        assert_eq!(exit_code, Some(17));
        assert!(stderr.contains("child stderr"));
        assert!(stderr.contains("manifest read failed"));
        assert!(stderr.contains("missing manifest"));
    }

    #[test]
    fn dynamic_hook_manifest_read_error_handles_empty_stderr() {
        let source: Error = Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "manifest denied",
        ));
        let err: Error = dynamic_hook_manifest_read_error(None, "", source);
        let Error::DynamicHookSubprocess { exit_code, stderr } = err else {
            panic!("expected subprocess error");
        };
        assert_eq!(exit_code, None);
        assert!(!stderr.starts_with('\n'));
        assert!(stderr.contains("manifest denied"));
    }

    #[test]
    fn capture_groups_deserializes_cextract_and_pytrace_fields() {
        let json: &str = "{\"cextract\":[{\"index\":0,\"size\":42,\"sha256\":\"abc\",\"pyc_path\":\"x.pyc\"}],\"pytrace\":[]}";
        let groups: CaptureGroups = serde_json::from_str(json).expect("parses");
        assert_eq!(groups.cextract.len(), 1);
        assert_eq!(groups.cextract[0].size, 42);
        assert!(groups.pytrace.is_empty());
        assert!(groups.monkeypatch.is_empty());
    }

    #[test]
    fn dynamic_hook_options_disable_flags_default_false() {
        let opts: DynamicHookOptions = DynamicHookOptions::default();
        assert!(!opts.disable_pytrace);
        assert!(!opts.disable_cextract);
    }

    #[test]
    fn dynamic_hook_default_is_disabled() {
        let opts: DynamicHookOptions = DynamicHookOptions::default();
        assert!(!opts.allow_dynamic);
    }
}
