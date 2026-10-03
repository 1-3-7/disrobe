use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::ExitStatus;
use std::time::Duration;

pub use disrobe_tool_process::{
    CaptureOutcome, CapturedStream, CommandSpec, Completion, ContainmentEvidence, Execution,
    ExecutionError, LaunchError, LaunchStage, LifecycleError, RuntimeFailure, StdinOutcome,
    WorkerStream,
};

#[derive(Debug)]
pub struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

pub fn run_captured<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
    max_capture_bytes: usize,
) -> std::io::Result<Option<CapturedOutput>> {
    capture_command(
        CommandSpec::new(program, timeout)
            .args(args.iter().map(|arg: &S| arg.as_ref().to_os_string()))
            .capture_limits(max_capture_bytes, max_capture_bytes),
    )
}

pub fn run_captured_with_env<S, I, K, V>(
    program: &Path,
    args: &[S],
    environment: I,
    timeout: Duration,
    max_capture_bytes: usize,
) -> std::io::Result<Option<CapturedOutput>>
where
    S: AsRef<OsStr>,
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let spec: CommandSpec = environment.into_iter().fold(
        CommandSpec::new(program, timeout),
        |spec: CommandSpec, (key, value): (K, V)| spec.env(key, value),
    );
    capture_command(
        spec.args(args.iter().map(|arg: &S| arg.as_ref().to_os_string()))
            .capture_limits(max_capture_bytes, max_capture_bytes),
    )
}

pub fn capture_command(spec: CommandSpec) -> std::io::Result<Option<CapturedOutput>> {
    let execution: Execution = spec.run().map_err(std::io::Error::other)?;
    let status: ExitStatus = match execution.completion {
        Completion::Exited(status) => status,
        Completion::TimedOut(_) => return Ok(None),
    };
    let stdout: Vec<u8> = legacy_capture(execution.stdout, "stdout")?;
    let stderr: Vec<u8> = legacy_capture(execution.stderr, "stderr")?;
    match execution.stdin {
        StdinOutcome::Closed | StdinOutcome::Delivered => {}
        StdinOutcome::Failed(source) => return Err(source),
        StdinOutcome::NotStarted => return Err(std::io::Error::other("stdin worker not started")),
        StdinOutcome::WorkerPanicked => {
            return Err(std::io::Error::other("stdin worker panicked"));
        }
        StdinOutcome::WorkerUnresponsive => {
            return Err(std::io::Error::other("stdin worker did not finish"));
        }
    }
    Ok(Some(CapturedOutput {
        stdout,
        stderr,
        exit_code: status.code(),
    }))
}

fn legacy_capture(outcome: CaptureOutcome, stream: &'static str) -> std::io::Result<Vec<u8>> {
    match outcome {
        CaptureOutcome::Complete(captured) if captured.truncated => Err(std::io::Error::other(
            format!("{stream} capture exceeded the configured limit"),
        )),
        CaptureOutcome::Complete(captured) => Ok(captured.bytes),
        CaptureOutcome::Failed { source, .. } => Err(source),
        CaptureOutcome::NotStarted => Err(std::io::Error::other(format!(
            "{stream} capture worker not started"
        ))),
        CaptureOutcome::WorkerPanicked => Err(std::io::Error::other(format!(
            "{stream} capture worker panicked"
        ))),
        CaptureOutcome::WorkerUnresponsive => Err(std::io::Error::other(format!(
            "{stream} capture worker did not finish"
        ))),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const TEST_CAPTURE_CAP: usize = 1024 * 1024;
    static PROCESS_TIMING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        panic!(
            "{} is not built; cargo builds it with this crate's integration tests, or run `cargo \
             build -p disrobe-core --bin disrobe-core-mock-proc` first, because this test never \
             starts cargo",
            candidate.display()
        );
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
        let _guard: std::sync::MutexGuard<'_, ()> = PROCESS_TIMING_TEST_LOCK
            .lock()
            .expect("lock process timing test");
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

    #[test]
    fn run_captured_rejects_a_truncated_stream() {
        let error: std::io::Error = run_captured(
            &mock_bin_path(),
            &["flood", "4096"],
            Duration::from_secs(5),
            1024,
        )
        .expect_err("legacy capture must not hide truncation");
        assert!(error.to_string().contains("stdout capture exceeded"));
    }

    #[test]
    fn run_captured_with_env_preserves_process_tree_containment() {
        let _guard: std::sync::MutexGuard<'_, ()> = PROCESS_TIMING_TEST_LOCK
            .lock()
            .expect("lock process timing test");
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-env-descendant")
                .expect("mkdir env descendant dir");
        let marker: PathBuf = scratch.path().join("env-descendant-marker");
        let marker_arg: String = marker.to_string_lossy().into_owned();
        let started: std::time::Instant = std::time::Instant::now();
        let result: Option<CapturedOutput> = run_captured_with_env(
            &mock_bin_path(),
            &["spawn-marker-pipe", &marker_arg, "1500"],
            [("DISROBE_TEST_ENV", "present")],
            Duration::from_millis(100),
            TEST_CAPTURE_CAP,
        )
        .expect("spawn env-capable process");
        let elapsed: Duration = started.elapsed();
        let marker_existed_at_return: bool = marker.exists();
        let _: std::io::Result<()> = std::fs::remove_file(&marker);
        assert!(result.is_none(), "the process tree must time out");
        assert!(
            !marker_existed_at_return,
            "the descendant must be terminated"
        );
        assert!(elapsed < Duration::from_secs(1), "timeout took {elapsed:?}");
    }

    #[test]
    fn run_captured_with_env_replaces_duplicate_child_variables() {
        #[cfg(unix)]
        let program: PathBuf = PathBuf::from("/usr/bin/env");
        #[cfg(windows)]
        let program: PathBuf = std::env::var_os("ComSpec").map_or_else(
            || PathBuf::from(r"C:\Windows\System32\cmd.exe"),
            PathBuf::from,
        );
        #[cfg(unix)]
        let args: &[&str] = &[];
        #[cfg(windows)]
        let args: &[&str] = &["/D", "/C", "set", "DISROBE_TEST_ENV"];
        let output: CapturedOutput = run_captured_with_env(
            &program,
            args,
            [
                ("DISROBE_TEST_ENV", "first"),
                ("DISROBE_TEST_ENV", "second"),
            ],
            Duration::from_secs(5),
            64 * 1024,
        )
        .expect("environment probe must spawn")
        .expect("environment probe must finish");
        let rendered: String = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        assert!(
            rendered
                .lines()
                .any(|line: &str| line.trim() == "disrobe_test_env=second"),
            "child environment did not receive the final override: {rendered}"
        );
        assert!(
            !rendered
                .lines()
                .any(|line: &str| line.trim() == "disrobe_test_env=first"),
            "child environment retained an earlier override: {rendered}"
        );
    }

    #[test]
    fn deadline_terminates_a_descendant_holding_the_capture_pipe() {
        let _guard: std::sync::MutexGuard<'_, ()> = PROCESS_TIMING_TEST_LOCK
            .lock()
            .expect("lock process timing test");
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-descendant-pipe")
                .expect("mkdir descendant pipe dir");
        let marker: PathBuf = scratch.path().join("late-marker");
        let marker_arg: String = marker.to_string_lossy().into_owned();
        let mock: PathBuf = mock_bin_path();
        let start: std::time::Instant = std::time::Instant::now();
        let result: Option<CapturedOutput> = run_captured(
            &mock,
            &["spawn-marker-pipe", &marker_arg, "1500"],
            Duration::from_millis(100),
            TEST_CAPTURE_CAP,
        )
        .expect("spawn parent for descendant pipe test");
        let elapsed: Duration = start.elapsed();
        let marker_existed_at_return: bool = marker.exists();
        let _: std::io::Result<()> = std::fs::remove_file(&marker);
        assert!(
            result.is_none(),
            "a deadline must report timeout even after the direct parent exits"
        );
        assert!(
            !marker_existed_at_return,
            "the contained descendant must be terminated before its delayed marker action"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "capture draining must not extend a 100ms deadline to {elapsed:?}"
        );
    }

    #[test]
    fn completion_waits_for_a_null_stdio_descendant_marker() {
        let _guard: std::sync::MutexGuard<'_, ()> = PROCESS_TIMING_TEST_LOCK
            .lock()
            .expect("lock process timing test");
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-descendant-null")
                .expect("mkdir descendant null dir");
        let marker: PathBuf = scratch.path().join("completion-marker");
        let marker_arg: String = marker.to_string_lossy().into_owned();
        let mock: PathBuf = mock_bin_path();
        let start: std::time::Instant = std::time::Instant::now();
        let result: Option<CapturedOutput> = run_captured(
            &mock,
            &["spawn-marker-null", &marker_arg, "500"],
            Duration::from_secs(5),
            TEST_CAPTURE_CAP,
        )
        .expect("spawn parent for null-stdio descendant test");
        let elapsed: Duration = start.elapsed();
        let marker_existed_at_return: bool = marker.exists();
        std::thread::sleep(Duration::from_millis(700));
        let marker_existed_eventually: bool = marker.exists();
        let _: std::io::Result<()> = std::fs::remove_file(&marker);
        assert!(result.is_some(), "the contained process set must complete");
        assert!(
            marker_existed_eventually,
            "the descendant fixture must prove that its delayed action ran"
        );
        assert!(
            marker_existed_at_return,
            "completion must wait until a null-stdio descendant finishes"
        );
        assert!(
            elapsed >= Duration::from_millis(450),
            "completion returned before the descendant marker delay: {elapsed:?}"
        );
    }

    #[test]
    fn typed_facade_caps_stdout_and_stderr_independently_while_draining() {
        let execution: Execution = CommandSpec::new(mock_bin_path(), Duration::from_secs(5))
            .args(["flood-both", "4096", "6144"])
            .capture_limits(1024, 2048)
            .run()
            .expect("run dual-stream flood");
        let Completion::Exited(status) = execution.completion else {
            panic!("dual-stream flood timed out");
        };
        assert!(status.success());
        assert_eq!(
            execution.containment.empty_process_set_proven,
            cfg!(windows)
        );
        let CaptureOutcome::Complete(stdout) = execution.stdout else {
            panic!("stdout capture did not complete");
        };
        let CaptureOutcome::Complete(stderr) = execution.stderr else {
            panic!("stderr capture did not complete");
        };
        assert_eq!(stdout.bytes.len(), 1024);
        assert!(stdout.truncated);
        assert_eq!(stderr.bytes.len(), 2048);
        assert!(stderr.truncated);
        assert!(stdout.bytes.iter().all(|byte: &u8| *byte == b'o'));
        assert!(stderr.bytes.iter().all(|byte: &u8| *byte == b'e'));
    }

    #[test]
    fn typed_facade_delivers_large_stdin_without_blocking_capture() {
        let input: Vec<u8> = (0..(256 * 1024))
            .map(|index: usize| b'a' + u8::try_from(index % 26).unwrap_or_default())
            .collect();
        let execution: Execution = CommandSpec::new(mock_bin_path(), Duration::from_secs(5))
            .arg("echo-stdin")
            .stdin(input.clone())
            .capture_limits(input.len(), 1024)
            .run()
            .expect("run stdin echo");
        assert!(matches!(execution.stdin, StdinOutcome::Delivered));
        let CaptureOutcome::Complete(stdout) = execution.stdout else {
            panic!("stdout capture did not complete");
        };
        assert_eq!(stdout.bytes, input);
        assert!(!stdout.truncated);
    }

    #[test]
    fn typed_facade_reports_a_closed_stdin_pipe() {
        let execution: Execution = CommandSpec::new(mock_bin_path(), Duration::from_secs(5))
            .arg("close-stdin")
            .stdin(vec![b'x'; 16 * 1024 * 1024])
            .capture_limits(1024, 1024)
            .run()
            .expect("run closed-stdin fixture");
        assert!(matches!(execution.stdin, StdinOutcome::Failed(_)));
    }

    #[test]
    fn typed_facade_retains_stderr_for_nonzero_exit() {
        let execution: Execution = CommandSpec::new(mock_bin_path(), Duration::from_secs(5))
            .args(["stderr-exit", "23", "formatter rejected input"])
            .capture_limits(1024, 1024)
            .run()
            .expect("run nonzero fixture");
        let Completion::Exited(status) = execution.completion else {
            panic!("nonzero fixture timed out");
        };
        assert_eq!(status.code(), Some(23));
        let CaptureOutcome::Complete(stderr) = execution.stderr else {
            panic!("stderr capture did not complete");
        };
        assert_eq!(stderr.bytes, b"formatter rejected input");
    }

    #[test]
    fn typed_facade_zero_deadline_returns_only_after_termination_proof() {
        let _guard: std::sync::MutexGuard<'_, ()> = PROCESS_TIMING_TEST_LOCK
            .lock()
            .expect("lock process timing test");
        let start: std::time::Instant = std::time::Instant::now();
        let execution: Execution = CommandSpec::new(mock_bin_path(), Duration::ZERO)
            .args(["sleep", "5"])
            .capture_limits(1024, 1024)
            .run()
            .expect("run zero-deadline fixture");
        assert!(matches!(execution.completion, Completion::TimedOut(_)));
        assert_eq!(
            execution.containment.empty_process_set_proven,
            cfg!(windows)
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn jobs_one_and_four_produce_identical_canonical_outputs() {
        fn run_one(mock: &Path, index: usize) -> Vec<u8> {
            let value: String = format!("job-{index}");
            let execution: Execution = CommandSpec::new(mock, Duration::from_secs(5))
                .args(["echo-args", &value])
                .capture_limits(1024, 1024)
                .run()
                .expect("run deterministic fixture");
            let CaptureOutcome::Complete(stdout) = execution.stdout else {
                panic!("deterministic stdout capture did not complete");
            };
            stdout.bytes
        }

        let mock: PathBuf = mock_bin_path();
        let serial: Vec<Vec<u8>> = (0..4).map(|index: usize| run_one(&mock, index)).collect();
        let parallel_workers: [std::thread::JoinHandle<Vec<u8>>; 4] =
            std::array::from_fn(|index: usize| {
                let worker_mock: PathBuf = mock.clone();
                std::thread::spawn(move || run_one(&worker_mock, index))
            });
        let parallel: Vec<Vec<u8>> = parallel_workers
            .into_iter()
            .map(|worker: std::thread::JoinHandle<Vec<u8>>| {
                worker.join().expect("deterministic worker")
            })
            .collect();
        assert_eq!(parallel, serial);
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_wrapper_preserves_metacharacter_argument() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-batch-wrapper")
                .expect("mkdir batch wrapper dir");
        let script: PathBuf = scratch.path().join("echo-argument.cmd");
        std::fs::write(
            &script,
            b"@echo off\r\n<nul set /p \"=%~1\"\r\nexit /b 0\r\n",
        )
        .expect("write batch wrapper");
        let argument: &str = "meta & | < > ^ %PATH% (x) ! tail";
        let execution: Execution = CommandSpec::new(&script, Duration::from_secs(5))
            .arg(argument)
            .capture_limits(4096, 4096)
            .run()
            .expect("run batch wrapper");
        let Completion::Exited(status) = execution.completion else {
            panic!("batch wrapper timed out");
        };
        let CaptureOutcome::Complete(stdout) = execution.stdout else {
            panic!("batch stdout capture did not complete");
        };
        let CaptureOutcome::Complete(stderr) = execution.stderr else {
            panic!("batch stderr capture did not complete");
        };
        assert!(
            status.success(),
            "batch wrapper exit={:?} stdout={:?} stderr={:?}",
            status.code(),
            String::from_utf8_lossy(&stdout.bytes),
            String::from_utf8_lossy(&stderr.bytes)
        );
        assert_eq!(String::from_utf8_lossy(&stdout.bytes), argument);
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_wrapper_rejects_an_unrepresentable_quote() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-batch-quote")
                .expect("mkdir batch quote dir");
        let script: PathBuf = scratch.path().join("echo-argument.cmd");
        std::fs::write(&script, b"@echo off\r\nexit /b 0\r\n").expect("write batch wrapper");
        let error: ExecutionError = CommandSpec::new(&script, Duration::from_secs(5))
            .arg("quote-\"")
            .run()
            .expect_err("batch quote must be rejected before spawn");
        assert!(matches!(
            error,
            ExecutionError::Launch(LaunchError::InvalidInput(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_wrapper_preserves_a_quoted_trailing_backslash() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-batch-backslash")
                .expect("mkdir batch wrapper dir");
        let script: PathBuf = scratch.path().join("echo-argument.cmd");
        std::fs::write(
            &script,
            b"@echo off\r\n<nul set /p \"=%~1\"\r\nexit /b 0\r\n",
        )
        .expect("write batch wrapper");
        let argument: &str = "C:\\path with space\\";
        let execution: Execution = CommandSpec::new(&script, Duration::from_secs(5))
            .arg(argument)
            .capture_limits(4096, 4096)
            .run()
            .expect("run batch backslash fixture");
        let CaptureOutcome::Complete(stdout) = execution.stdout else {
            panic!("batch stdout capture did not complete");
        };
        assert_eq!(String::from_utf8_lossy(&stdout.bytes), argument);
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_wrapper_preserves_percent_in_its_path() {
        let scratch: crate::scratch::ScratchDir =
            crate::scratch::ScratchDir::create("disrobe-core-batch-percent")
                .expect("mkdir batch wrapper dir");
        let script: PathBuf = scratch.path().join("echo-%PATH%-argument.cmd");
        std::fs::write(
            &script,
            b"@echo off\r\n<nul set /p \"=%~1\"\r\nexit /b 0\r\n",
        )
        .expect("write batch wrapper");
        let execution: Execution = CommandSpec::new(&script, Duration::from_secs(5))
            .arg("literal")
            .capture_limits(4096, 4096)
            .run()
            .expect("run percent-path batch fixture");
        let Completion::Exited(status) = execution.completion else {
            panic!("percent-path batch wrapper timed out");
        };
        assert!(status.success());
        let CaptureOutcome::Complete(stdout) = execution.stdout else {
            panic!("batch stdout capture did not complete");
        };
        assert_eq!(stdout.bytes, b"literal");
    }

    #[cfg(windows)]
    #[test]
    fn windows_argument_with_interior_nul_is_rejected_before_spawn() {
        use std::os::windows::ffi::OsStringExt as _;

        let invalid: std::ffi::OsString =
            std::ffi::OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]);
        let error: ExecutionError = CommandSpec::new(mock_bin_path(), Duration::from_secs(5))
            .arg(invalid)
            .run()
            .expect_err("interior nul must fail");
        assert!(matches!(
            error,
            ExecutionError::Launch(LaunchError::InvalidInput(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_executable_arguments_follow_crt_quoting_rules() {
        let arguments: [&str; 6] = [
            "",
            "plain",
            "two words",
            "quote-\"inside",
            r"trailing slash\",
            "unicode-λ",
        ];
        let execution: Execution = CommandSpec::new(mock_bin_path(), Duration::from_secs(5))
            .arg("echo-args")
            .args(arguments)
            .capture_limits(4096, 4096)
            .run()
            .expect("run Windows CRT quoting fixture");
        let CaptureOutcome::Complete(stdout) = execution.stdout else {
            panic!("Windows CRT quoting stdout capture did not complete");
        };
        let expected: String = format!("{}\n", arguments.join("\n"));
        assert_eq!(String::from_utf8_lossy(&stdout.bytes), expected);
    }
}
