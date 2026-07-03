use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::{MAX_JSON_FILE_BYTES, read_file_bounded};

const HELPER_SCRIPT: &str = include_str!("v6v7_dynamic_hook.py");
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MIN_PYTHON: (u8, u8, u8) = (3, 9, 7);
const MAX_DYNAMIC_CAPTURE: usize = 4 * 1024 * 1024;
const CAPTURE_READ_CHUNK: usize = 8192;

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

    let helper_path: PathBuf = out_dir.join(".disrobe_v6v7_helper.py");
    std::fs::write(&helper_path, HELPER_SCRIPT)?;
    let helper_abs: PathBuf = helper_path
        .canonicalize()
        .unwrap_or_else(|_| helper_path.clone());

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

    let start: Instant = Instant::now();
    let mut child: std::process::Child = cmd.spawn().map_err(|e| {
        Error::KeyExtraction(format!("failed to spawn dynamic hook interpreter: {e}"))
    })?;
    let stdout_reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>> =
        spawn_capture_reader(child.stdout.take());
    let stderr_reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>> =
        spawn_capture_reader(child.stderr.take());

    let exit_status: std::process::ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= options.timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    drop(join_capture_reader(stdout_reader, "stdout")?);
                    drop(join_capture_reader(stderr_reader, "stderr")?);
                    return Err(Error::DynamicHookTimedOut {
                        secs: options.timeout.as_secs(),
                    });
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(Error::KeyExtraction(format!("wait-child failed: {e}")));
            }
        }
    };

    drop(join_capture_reader(stdout_reader, "stdout")?);
    let stderr_buf: Vec<u8> = join_capture_reader(stderr_reader, "stderr")?;
    let stderr_excerpt: String = String::from_utf8_lossy(&stderr_buf).into_owned();
    let exit_code: Option<i32> = exit_status.code();

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
    matches!(cmd.output(), Ok(out) if out.status.success())
}

fn python_version(spec: &InterpreterSpec) -> Result<(u8, u8, u8)> {
    let mut cmd: Command = Command::new(&spec.exe);
    for arg in &spec.version_args {
        cmd.arg(arg);
    }
    cmd.arg("-c").arg(
        "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}')",
    );
    let output: std::process::Output = cmd.output()?;
    if !output.status.success() {
        return Err(Error::KeyExtraction(
            "could not query python version".to_owned(),
        ));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    parse_version(text.trim())
        .ok_or_else(|| Error::KeyExtraction(format!("could not parse python version: {text:?}")))
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

fn read_capped_output<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let read: usize = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining: usize = MAX_DYNAMIC_CAPTURE.saturating_sub(out.len());
        if remaining > 0 {
            let keep: usize = read.min(remaining);
            out.extend_from_slice(&chunk[..keep]);
        }
    }
    Ok(out)
}

fn spawn_capture_reader<R>(reader: Option<R>) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        reader.map_or_else(|| Ok(Vec::new()), |stream: R| read_capped_output(stream))
    })
}

fn join_capture_reader(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| Error::KeyExtraction(format!("dynamic hook {stream} reader panicked")))?
        .map_err(|e: std::io::Error| {
            Error::KeyExtraction(format!("dynamic hook {stream} read failed: {e}"))
        })
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
    use super::*;

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
    fn dynamic_capture_reader_stores_fixed_limit() -> std::io::Result<()> {
        let payload: Vec<u8> = vec![b'y'; MAX_DYNAMIC_CAPTURE + 1024];
        let captured: Vec<u8> = read_capped_output(std::io::Cursor::new(payload))?;
        assert_eq!(captured.len(), MAX_DYNAMIC_CAPTURE);
        assert!(captured.iter().all(|byte: &u8| *byte == b'y'));
        Ok(())
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
