use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

use crate::bytecode::version::PyVersion as DecompileVersion;
use crate::roundtrip::{self, Verdict};

const PROBE_TIMEOUT_SECS: u64 = 5;
const RECOMPILE_TIMEOUT_SECS: u64 = 60;
const MAX_PROBE_CAPTURE: usize = 1024 * 1024;
const CAPTURE_READ_CHUNK: usize = 8192;

struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
}

fn wait_with_output_timeout(mut child: Child, timeout: Duration) -> Option<CapturedOutput> {
    let stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>> = child
        .stdout
        .take()
        .map(|pipe: std::process::ChildStdout| std::thread::spawn(move || read_capped(pipe)));
    let stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>> = child
        .stderr
        .take()
        .map(|pipe: std::process::ChildStderr| std::thread::spawn(move || read_capped(pipe)));
    let deadline: Instant = Instant::now() + timeout;
    let status: std::process::ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _: std::io::Result<()> = child.kill();
                    let _: std::io::Result<std::process::ExitStatus> = child.wait();
                    drop(join_capture(stdout));
                    drop(join_capture(stderr));
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _: std::io::Result<()> = child.kill();
                let _: std::io::Result<std::process::ExitStatus> = child.wait();
                drop(join_capture(stdout));
                drop(join_capture(stderr));
                return None;
            }
        }
    };
    Some(CapturedOutput {
        stdout: join_capture(stdout)?,
        stderr: join_capture(stderr)?,
        exit_code: status.code(),
    })
}

fn join_capture(handle: Option<JoinHandle<std::io::Result<Vec<u8>>>>) -> Option<Vec<u8>> {
    handle.map_or_else(
        || Some(Vec::new()),
        |handle: JoinHandle<std::io::Result<Vec<u8>>>| match handle.join() {
            Ok(Ok(bytes)) => Some(bytes),
            Ok(Err(_)) | Err(_) => None,
        },
    )
}

fn read_capped<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(MAX_PROBE_CAPTURE.min(CAPTURE_READ_CHUNK));
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let n: usize = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let remaining: usize = MAX_PROBE_CAPTURE.saturating_sub(out.len());
        let keep: usize = remaining.min(n);
        out.extend_from_slice(&chunk[..keep]);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundtripStatus {
    Perfect,
    Semantic,
    CodeDiff { detail: String },
    NoInterpreter { hint: String },
    RecompileFailed { stderr: String },
    Skipped,
}

impl RoundtripStatus {
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Perfect => "perfect",
            Self::Semantic => "semantic",
            Self::CodeDiff { .. } => "code-diff",
            Self::NoInterpreter { .. } => "no-interpreter",
            Self::RecompileFailed { .. } => "recompile-failed",
            Self::Skipped => "skipped",
        }
    }
}

#[must_use]
pub fn roundtrip_skipped() -> RoundtripOutcome {
    RoundtripOutcome {
        status: RoundtripStatus::Skipped,
        interpreter_path: None,
        interpreter_version: None,
    }
}

#[derive(Debug, Clone)]
pub struct RoundtripOutcome {
    pub status: RoundtripStatus,
    pub interpreter_path: Option<PathBuf>,
    pub interpreter_version: Option<String>,
}

#[must_use]
pub fn roundtrip_native(
    recovered_source: &str,
    original_code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> RoundtripOutcome {
    let Some((interpreter, ver_label)): Option<(PathBuf, String)> =
        locate_interpreter(marshal_version)
    else {
        return RoundtripOutcome {
            status: RoundtripStatus::NoInterpreter {
                hint: format!(
                    "no python{}.{} on PATH",
                    marshal_version.major, marshal_version.minor
                ),
            },
            interpreter_path: None,
            interpreter_version: None,
        };
    };

    match recompile_via_interpreter(&interpreter, recovered_source) {
        Ok(recompiled) => {
            let verdict: Verdict =
                roundtrip::semantic_equiv(original_code, &recompiled, marshal_version);
            let status: RoundtripStatus = match verdict {
                Verdict::Perfect => RoundtripStatus::Perfect,
                Verdict::Semantic => RoundtripStatus::Semantic,
                Verdict::CodeDiff(d) => RoundtripStatus::CodeDiff {
                    detail: format!(
                        "{} @ idx {}: {} vs {} ({})",
                        d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                    ),
                },
            };
            let _: &DecompileVersion = decompile_version;
            RoundtripOutcome {
                status,
                interpreter_path: Some(interpreter),
                interpreter_version: Some(ver_label),
            }
        }
        Err(stderr) => RoundtripOutcome {
            status: RoundtripStatus::RecompileFailed { stderr },
            interpreter_path: Some(interpreter),
            interpreter_version: Some(ver_label),
        },
    }
}

fn locate_interpreter(target: MarshalVersion) -> Option<(PathBuf, String)> {
    let candidates: [String; 4] = [
        format!("python{}.{}", target.major, target.minor),
        format!("python{}", target.major),
        "python3".to_owned(),
        "python".to_owned(),
    ];
    for cand in &candidates {
        let Some(found): Option<(PathBuf, MarshalVersion)> = probe_python(cand) else {
            continue;
        };
        if found.1.major == target.major && found.1.minor == target.minor {
            let label: String = format!("python{}.{}", found.1.major, found.1.minor);
            return Some((found.0, label));
        }
    }
    None
}

fn probe_python(name: &str) -> Option<(PathBuf, MarshalVersion)> {
    let exe: PathBuf = which_on_path(name)?;
    let child: Child = Command::new(&exe)
        .args([
            "-c",
            "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let captured: CapturedOutput =
        wait_with_output_timeout(child, Duration::from_secs(PROBE_TIMEOUT_SECS))?;
    if captured.exit_code != Some(0) {
        return None;
    }
    let text: String = String::from_utf8_lossy(&captured.stdout).trim().to_owned();
    let (maj, min): (&str, &str) = text.split_once('.')?;
    let major: u8 = maj.parse().ok()?;
    let minor: u8 = min.parse().ok()?;
    Some((exe, MarshalVersion { major, minor }))
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() || !dir.is_absolute() {
            continue;
        }
        for variant in [exe, &format!("{exe}.exe")] {
            let candidate: PathBuf = dir.join(variant);
            if candidate.is_absolute() && candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn py_path_literal(path: &Path) -> String {
    let s: String = path.to_string_lossy().into_owned();
    let escaped: String = s.replace('\\', r"\\").replace('\'', r"\'");
    format!("'{escaped}'")
}

static ROUNDTRIP_SEQ: AtomicU64 = AtomicU64::new(0);

fn recompile_via_interpreter(interpreter: &Path, source: &str) -> Result<CodeObject, String> {
    let tmp_root: PathBuf = std::env::temp_dir();
    let pid: u32 = std::process::id();
    let seq: u64 = ROUNDTRIP_SEQ.fetch_add(1, Ordering::Relaxed);
    let src_path: PathBuf = tmp_root.join(format!("disrobe-rt-{pid}-{seq}.py"));
    let pyc_path: PathBuf = tmp_root.join(format!("disrobe-rt-{pid}-{seq}.pyc"));
    std::fs::write(&src_path, source.as_bytes()).map_err(|e| format!("write temp source: {e}"))?;
    let src_lit: String = py_path_literal(&src_path);
    let pyc_lit: String = py_path_literal(&pyc_path);
    let script: String = format!(
        "import py_compile,sys\n\
try:\n    py_compile.compile({src_lit}, cfile={pyc_lit}, doraise=True)\n\
except Exception as e:\n    sys.stderr.write(str(e));sys.exit(2)\n"
    );
    let child: Child = Command::new(interpreter)
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn interpreter: {e}"))?;
    let captured: CapturedOutput =
        wait_with_output_timeout(child, Duration::from_secs(RECOMPILE_TIMEOUT_SECS)).ok_or_else(
            || format!("interpreter timed out after {RECOMPILE_TIMEOUT_SECS}s and was killed"),
        )?;
    let _: std::io::Result<()> = std::fs::remove_file(&src_path);
    if captured.exit_code != Some(0) {
        let _: std::io::Result<()> = std::fs::remove_file(&pyc_path);
        let stderr: String = String::from_utf8_lossy(&captured.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("py_compile exit {:?}", captured.exit_code)
        } else {
            stderr
        });
    }
    let bytes: Vec<u8> = std::fs::read(&pyc_path).map_err(|e| format!("read pyc: {e}"))?;
    let _: std::io::Result<()> = std::fs::remove_file(&pyc_path);
    let pyc: PycFile =
        read_pyc(&bytes).map_err(|e: disrobe_py_marshal::Error| format!("parse pyc: {e}"))?;
    match pyc.code {
        Object::Code(boxed) => Ok(*boxed),
        other => Err(format!("recompiled pyc lacks code object: {other:?}")),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn mock_bin_path() -> PathBuf {
        static RESOLVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_disrobe-pass-py-decompile-mock-proc") {
            let p_buf: PathBuf = PathBuf::from(p);
            if p_buf.is_file() {
                return p_buf;
            }
        }
        let _resolve_guard: std::sync::MutexGuard<'_, ()> = RESOLVE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exe_name: &str = if cfg!(windows) {
            "disrobe-pass-py-decompile-mock-proc.exe"
        } else {
            "disrobe-pass-py-decompile-mock-proc"
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
                "disrobe-pass-py-decompile",
                "--bin",
                "disrobe-pass-py-decompile-mock-proc",
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

    fn spawn_mock(args: &[&str]) -> Child {
        Command::new(mock_bin_path())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mock-proc")
    }

    #[test]
    fn timeout_actually_kills_a_sleeping_child() {
        let child: Child = spawn_mock(&["sleep", "5"]);
        let start: Instant = Instant::now();
        let result: Option<CapturedOutput> =
            wait_with_output_timeout(child, Duration::from_millis(300));
        let elapsed: Duration = start.elapsed();
        eprintln!(
            "[evidence] py-decompile timeout test: elapsed={elapsed:?} deadline=300ms sleep_requested=5s killed={}",
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
    fn output_cap_truncates_a_flooding_child() {
        let flood_bytes: usize = MAX_PROBE_CAPTURE * 3;
        let child: Child = spawn_mock(&["flood", &flood_bytes.to_string()]);
        let out: CapturedOutput = wait_with_output_timeout(child, Duration::from_secs(20))
            .expect("flood child must complete within timeout");
        eprintln!(
            "[evidence] py-decompile cap test: child_wrote={flood_bytes} captured={} cap={MAX_PROBE_CAPTURE}",
            out.stdout.len()
        );
        assert_eq!(
            out.stdout.len(),
            MAX_PROBE_CAPTURE,
            "captured stdout must be truncated to the cap, not the full {flood_bytes} bytes written"
        );
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn metacharacter_argv_passes_through_literally() {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("disrobe-pydecomp-metachar-{}", std::process::id()));
        let _: std::io::Result<()> = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir metachar dir");
        let weird_name: &str = "disrobe-metachar-'; & $HOME `id` (test) !bang %VAR% done.txt";
        let weird_path: PathBuf = dir.join(weird_name);
        std::fs::write(&weird_path, b"payload").expect("write metachar file");

        let child: Child = spawn_mock(&["echo-args", &weird_path.to_string_lossy()]);
        let out: CapturedOutput = wait_with_output_timeout(child, Duration::from_secs(5))
            .expect("echo-args child must complete");
        let reported: String = String::from_utf8_lossy(&out.stdout).trim_end().to_owned();
        eprintln!(
            "[evidence] py-decompile metachar test: sent={:?} received={reported:?}",
            weird_path.to_string_lossy()
        );
        assert_eq!(
            reported,
            weird_path.to_string_lossy(),
            "the child must receive the metacharacter-laden path as a single literal argv element"
        );
        let _: std::io::Result<()> = std::fs::remove_dir_all(&dir);
    }
}
