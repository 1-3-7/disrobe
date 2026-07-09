use std::process::Child;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_CAPTURE_OUTPUT: usize = 1024 * 1024;
const CAPTURE_READ_CHUNK: usize = 8192;

#[derive(Debug)]
pub(crate) struct CapturedOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: Option<i32>,
}

pub(crate) fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
) -> Option<CapturedOutput> {
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
                    let _: Result<(), std::io::Error> = child.kill();
                    let _: Result<std::process::ExitStatus, std::io::Error> = child.wait();
                    drop(join_capture(stdout));
                    drop(join_capture(stderr));
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _: Result<(), std::io::Error> = child.kill();
                let _: Result<std::process::ExitStatus, std::io::Error> = child.wait();
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
        |handle| match handle.join() {
            Ok(Ok(bytes)) => Some(bytes),
            Ok(Err(_)) | Err(_) => None,
        },
    )
}

fn read_capped<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(MAX_CAPTURE_OUTPUT.min(CAPTURE_READ_CHUNK));
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let n: usize = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let remaining: usize = MAX_CAPTURE_OUTPUT.saturating_sub(out.len());
        let keep: usize = remaining.min(n);
        out.extend_from_slice(&chunk[..keep]);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Stdio;

    use super::*;

    #[test]
    fn read_capped_retains_only_limit() {
        let payload: Vec<u8> = vec![b'x'; MAX_CAPTURE_OUTPUT + 1024];
        let out: Vec<u8> = read_capped(std::io::Cursor::new(payload)).expect("read");
        assert_eq!(out.len(), MAX_CAPTURE_OUTPUT);
    }

    fn mock_bin_path() -> PathBuf {
        static RESOLVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_disrobe-cli-mock-proc") {
            let p_buf: PathBuf = PathBuf::from(p);
            if p_buf.is_file() {
                return p_buf;
            }
        }
        let _resolve_guard: std::sync::MutexGuard<'_, ()> = RESOLVE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exe_name: &str = if cfg!(windows) {
            "disrobe-cli-mock-proc.exe"
        } else {
            "disrobe-cli-mock-proc"
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
                "disrobe-cli",
                "--bin",
                "disrobe-cli-mock-proc",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn cargo build for mock-proc");
        assert!(status.success(), "cargo build disrobe-cli-mock-proc failed");
        assert!(candidate.is_file(), "mock-proc binary not at expected path");
        candidate
    }

    fn spawn_mock(args: &[&str]) -> Child {
        std::process::Command::new(mock_bin_path())
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
        let start: std::time::Instant = std::time::Instant::now();
        let result: Option<CapturedOutput> =
            wait_with_output_timeout(child, Duration::from_millis(300));
        let elapsed: Duration = start.elapsed();
        eprintln!(
            "[evidence] disrobe-cli timeout test: elapsed={elapsed:?} deadline=300ms sleep_requested=5s killed={}",
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
        let flood_bytes: usize = MAX_CAPTURE_OUTPUT * 3;
        let child: Child = spawn_mock(&["flood", &flood_bytes.to_string()]);
        let out: CapturedOutput = wait_with_output_timeout(child, Duration::from_secs(20))
            .expect("flood child must complete within timeout");
        eprintln!(
            "[evidence] disrobe-cli cap test: child_wrote={flood_bytes} captured={} cap={MAX_CAPTURE_OUTPUT}",
            out.stdout.len()
        );
        assert_eq!(
            out.stdout.len(),
            MAX_CAPTURE_OUTPUT,
            "captured stdout must be truncated to the cap, not the full {flood_bytes} bytes written"
        );
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn metacharacter_argv_passes_through_literally() {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("disrobe-cli-metachar-{}", std::process::id()));
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
            "[evidence] disrobe-cli metachar test: sent={:?} received={reported:?}",
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
