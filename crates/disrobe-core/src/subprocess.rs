use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

const CAPTURE_READ_CHUNK: usize = 8192;

#[derive(Debug)]
pub struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
    max_capture_bytes: usize,
) -> Option<CapturedOutput> {
    use wait_timeout::ChildExt as _;

    let stdout: Option<JoinHandle<Vec<u8>>> = child
        .stdout
        .take()
        .map(|pipe: ChildStdout| std::thread::spawn(move || read_capped(pipe, max_capture_bytes)));
    let stderr: Option<JoinHandle<Vec<u8>>> = child
        .stderr
        .take()
        .map(|pipe: ChildStderr| std::thread::spawn(move || read_capped(pipe, max_capture_bytes)));
    let Some(status): Option<ExitStatus> = child.wait_timeout(timeout).ok().flatten() else {
        let _: std::io::Result<()> = child.kill();
        let _: std::io::Result<ExitStatus> = child.wait();
        drop(join_capture(stdout));
        drop(join_capture(stderr));
        return None;
    };
    Some(CapturedOutput {
        stdout: join_capture(stdout)?,
        stderr: join_capture(stderr)?,
        exit_code: status.code(),
    })
}

#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
    max_capture_bytes: usize,
) -> Option<CapturedOutput> {
    let stdout: Option<JoinHandle<Vec<u8>>> = child
        .stdout
        .take()
        .map(|pipe: ChildStdout| std::thread::spawn(move || read_capped(pipe, max_capture_bytes)));
    let stderr: Option<JoinHandle<Vec<u8>>> = child
        .stderr
        .take()
        .map(|pipe: ChildStderr| std::thread::spawn(move || read_capped(pipe, max_capture_bytes)));
    let deadline: std::time::Instant = std::time::Instant::now() + timeout;
    let status: ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _: std::io::Result<()> = child.kill();
                    let _: std::io::Result<ExitStatus> = child.wait();
                    drop(join_capture(stdout));
                    drop(join_capture(stderr));
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _: std::io::Result<()> = child.kill();
                let _: std::io::Result<ExitStatus> = child.wait();
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

pub fn run_captured<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
    max_capture_bytes: usize,
) -> std::io::Result<Option<CapturedOutput>> {
    let child: Child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(wait_with_output_timeout(child, timeout, max_capture_bytes))
}

fn join_capture(handle: Option<JoinHandle<Vec<u8>>>) -> Option<Vec<u8>> {
    handle.map_or_else(
        || Some(Vec::new()),
        |handle: JoinHandle<Vec<u8>>| handle.join().ok(),
    )
}

fn read_capped<R: Read>(mut reader: R, max_capture_bytes: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(max_capture_bytes.min(CAPTURE_READ_CHUNK));
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let n: usize = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let remaining: usize = max_capture_bytes.saturating_sub(out.len());
        let keep: usize = remaining.min(n);
        out.extend_from_slice(&chunk[..keep]);
    }
    out
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const TEST_CAPTURE_CAP: usize = 1024 * 1024;

    fn mock_bin_path() -> PathBuf {
        static RESOLVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_disrobe-core-mock-proc") {
            let p_buf: PathBuf = PathBuf::from(p);
            if p_buf.is_file() {
                return p_buf;
            }
        }
        let _resolve_guard: std::sync::MutexGuard<'_, ()> = RESOLVE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exe_name: &str = if cfg!(windows) {
            "disrobe-core-mock-proc.exe"
        } else {
            "disrobe-core-mock-proc"
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
                "disrobe-core",
                "--bin",
                "disrobe-core-mock-proc",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn cargo build for mock-proc");
        assert!(
            status.success(),
            "cargo build disrobe-core-mock-proc failed"
        );
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

    struct FlakyReader {
        chunks: Vec<std::io::Result<Vec<u8>>>,
    }

    impl Read for FlakyReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.chunks.is_empty() {
                return Ok(0);
            }
            match self.chunks.remove(0) {
                Ok(bytes) => {
                    let n: usize = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        }
    }

    #[test]
    fn read_capped_stops_on_read_error_and_keeps_partial_data() {
        let reader: FlakyReader = FlakyReader {
            chunks: vec![
                Ok(b"partial-output-before-the-crash".to_vec()),
                Err(std::io::Error::other("simulated broken pipe")),
                Ok(b"unreachable-data-after-the-error".to_vec()),
            ],
        };
        let out: Vec<u8> = read_capped(reader, TEST_CAPTURE_CAP);
        assert_eq!(
            out, b"partial-output-before-the-crash",
            "a mid-read error must stop the read and keep already-captured bytes, not discard them"
        );
    }

    #[test]
    fn timeout_actually_kills_a_sleeping_child() {
        let child: Child = spawn_mock(&["sleep", "5"]);
        let start: std::time::Instant = std::time::Instant::now();
        let result: Option<CapturedOutput> =
            wait_with_output_timeout(child, Duration::from_millis(300), TEST_CAPTURE_CAP);
        let elapsed: Duration = start.elapsed();
        eprintln!(
            "[evidence] disrobe-core subprocess timeout test: elapsed={elapsed:?} deadline=300ms sleep_requested=5s killed={}",
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
        let flood_bytes: usize = TEST_CAPTURE_CAP * 3;
        let child: Child = spawn_mock(&["flood", &flood_bytes.to_string()]);
        let out: CapturedOutput =
            wait_with_output_timeout(child, Duration::from_secs(20), TEST_CAPTURE_CAP)
                .expect("flood child must complete within timeout");
        eprintln!(
            "[evidence] disrobe-core subprocess cap test: child_wrote={flood_bytes} captured={} cap={TEST_CAPTURE_CAP}",
            out.stdout.len()
        );
        assert_eq!(
            out.stdout.len(),
            TEST_CAPTURE_CAP,
            "captured stdout must be truncated to the cap, not the full {flood_bytes} bytes written"
        );
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn run_captured_spawns_waits_and_captures_argv_only() {
        let mock: PathBuf = mock_bin_path();
        let out: CapturedOutput = run_captured(
            &mock,
            &["echo-args", "hello-from-run-captured"],
            Duration::from_secs(5),
            TEST_CAPTURE_CAP,
        )
        .expect("spawn must succeed")
        .expect("child must complete within timeout");
        let reported: String = String::from_utf8_lossy(&out.stdout).trim_end().to_owned();
        eprintln!("[evidence] disrobe-core run_captured test: reported={reported:?}");
        assert_eq!(reported, "hello-from-run-captured");
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn run_captured_metacharacter_argv_passes_through_literally() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-metachar")
                .expect("mkdir metachar dir");
        let dir: PathBuf = scratch.path().to_path_buf();
        let weird_name: &str = "disrobe-metachar-'; & $HOME `id` (test) !bang %VAR% done.txt";
        let weird_path: PathBuf = dir.join(weird_name);
        std::fs::write(&weird_path, b"payload").expect("write metachar file");

        let mock: PathBuf = mock_bin_path();
        let out: CapturedOutput = run_captured(
            &mock,
            &["echo-args", &weird_path.to_string_lossy()],
            Duration::from_secs(5),
            TEST_CAPTURE_CAP,
        )
        .expect("spawn must succeed")
        .expect("echo-args child must complete");
        let reported: String = String::from_utf8_lossy(&out.stdout).trim_end().to_owned();
        eprintln!(
            "[evidence] disrobe-core run_captured metachar test: sent={:?} received={reported:?}",
            weird_path.to_string_lossy()
        );
        assert_eq!(
            reported,
            weird_path.to_string_lossy(),
            "the child must receive the metacharacter-laden path as a single literal argv element"
        );
    }

    #[test]
    fn run_captured_honors_timeout_on_a_sleeping_child() {
        let mock: PathBuf = mock_bin_path();
        let start: std::time::Instant = std::time::Instant::now();
        let out: Option<CapturedOutput> = run_captured(
            &mock,
            &["sleep", "5"],
            Duration::from_millis(300),
            TEST_CAPTURE_CAP,
        )
        .expect("spawn must succeed");
        let elapsed: Duration = start.elapsed();
        eprintln!(
            "[evidence] disrobe-core run_captured timeout test: elapsed={elapsed:?} killed={}",
            out.is_none()
        );
        assert!(
            out.is_none(),
            "sleeping child must be killed by run_captured"
        );
        assert!(elapsed < Duration::from_secs(2));
    }
}
