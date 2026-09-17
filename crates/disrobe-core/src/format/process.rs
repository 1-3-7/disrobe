#[cfg(not(target_arch = "wasm32"))]
pub(super) use native::{run_or_fail, tool_available};

#[cfg(target_arch = "wasm32")]
pub(super) use wasm::{run_or_fail, tool_available};

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{LazyLock, RwLock};
    use std::time::Duration;

    use crate::format::FormatError;
    use crate::subprocess::{CaptureOutcome, CommandSpec, Completion, Execution, StdinOutcome};

    const MAX_CAPTURE_OUTPUT: usize = 4 * 1024 * 1024;

    #[derive(Debug)]
    struct SubprocessOutput {
        stdout: String,
        stderr: String,
        exit: i32,
        success: bool,
    }

    static AVAILABILITY_CACHE: LazyLock<RwLock<BTreeMap<&'static str, bool>>> =
        LazyLock::new(|| RwLock::new(BTreeMap::new()));

    #[must_use]
    fn which_binary(binary: &'static str) -> Option<PathBuf> {
        let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            for ext in candidate_extensions() {
                let candidate: PathBuf = dir.join(format!("{binary}{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    #[cfg(windows)]
    const fn candidate_extensions() -> &'static [&'static str] {
        &["", ".exe", ".bat", ".cmd"]
    }

    #[cfg(not(windows))]
    const fn candidate_extensions() -> &'static [&'static str] {
        &[""]
    }

    #[must_use]
    pub(in crate::format) fn tool_available(binary: &'static str) -> bool {
        if let Ok(cache) = AVAILABILITY_CACHE.read()
            && let Some(found) = cache.get(binary)
        {
            return *found;
        }
        let present: bool = which_binary(binary).is_some();
        if let Ok(mut cache) = AVAILABILITY_CACHE.write() {
            let _: Option<bool> = cache.insert(binary, present);
        }
        present
    }

    fn run_formatter_stdio(
        binary: &'static str,
        args: &[&str],
        input: &str,
        timeout_secs: u32,
    ) -> Result<SubprocessOutput, FormatError> {
        let resolved: PathBuf = which_binary(binary).ok_or(FormatError::ToolMissing(binary))?;
        let timeout: Duration = Duration::from_secs(u64::from(timeout_secs));
        let execution: Execution = CommandSpec::new(resolved, timeout)
            .args(args.iter().copied())
            .stdin(input.as_bytes().to_vec())
            .capture_limits(MAX_CAPTURE_OUTPUT, MAX_CAPTURE_OUTPUT)
            .run()
            .map_err(|error| FormatError::ToolFailed {
                stderr: error.to_string(),
                exit: -1,
            })?;
        map_execution(execution)
    }

    fn map_execution(execution: Execution) -> Result<SubprocessOutput, FormatError> {
        let Execution {
            completion,
            stdin,
            stdout,
            stderr,
            ..
        } = execution;
        let status: std::process::ExitStatus = match completion {
            Completion::Exited(status) => status,
            Completion::TimedOut(_) => return Err(FormatError::Timeout),
        };
        let stdout: Vec<u8> = capture_bytes(stdout, "stdout")?;
        let stderr: Vec<u8> = capture_bytes(stderr, "stderr")?;
        let exit: i32 = status.code().unwrap_or(-1);
        let output: SubprocessOutput = SubprocessOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit,
            success: status.success(),
        };
        if !output.success {
            return Ok(output);
        }
        match stdin {
            StdinOutcome::Delivered => Ok(output),
            StdinOutcome::Failed(source) => Err(FormatError::ToolFailed {
                stderr: format!("formatter stdin write failed: {source}"),
                exit,
            }),
            StdinOutcome::Closed
            | StdinOutcome::NotStarted
            | StdinOutcome::WorkerPanicked
            | StdinOutcome::WorkerUnresponsive => Err(FormatError::ToolFailed {
                stderr: "formatter stdin was not delivered".to_owned(),
                exit,
            }),
        }
    }

    fn capture_bytes(
        outcome: CaptureOutcome,
        stream: &'static str,
    ) -> Result<Vec<u8>, FormatError> {
        match outcome {
            CaptureOutcome::Complete(captured) if captured.truncated => {
                Err(FormatError::ToolFailed {
                    stderr: format!(
                        "formatter {stream} capture exceeded the {MAX_CAPTURE_OUTPUT}-byte limit"
                    ),
                    exit: -1,
                })
            }
            CaptureOutcome::Complete(captured) => Ok(captured.bytes),
            CaptureOutcome::Failed { source, .. } => Err(FormatError::ToolFailed {
                stderr: format!("formatter {stream} capture failed: {source}"),
                exit: -1,
            }),
            CaptureOutcome::NotStarted => Err(FormatError::ToolFailed {
                stderr: format!("formatter {stream} capture did not start"),
                exit: -1,
            }),
            CaptureOutcome::WorkerPanicked => Err(FormatError::ToolFailed {
                stderr: format!("formatter {stream} capture worker panicked"),
                exit: -1,
            }),
            CaptureOutcome::WorkerUnresponsive => Err(FormatError::ToolFailed {
                stderr: format!("formatter {stream} capture worker did not finish"),
                exit: -1,
            }),
        }
    }

    pub(in crate::format) fn run_or_fail(
        binary: &'static str,
        args: &[&str],
        input: &str,
        timeout_secs: u32,
    ) -> Result<String, FormatError> {
        let out: SubprocessOutput = run_formatter_stdio(binary, args, input, timeout_secs)?;
        if !out.success {
            return Err(FormatError::ToolFailed {
                stderr: out.stderr,
                exit: out.exit,
            });
        }
        Ok(out.stdout)
    }

    #[cfg(test)]
    #[allow(clippy::expect_used, clippy::panic)]
    mod tests {
        use std::io;
        use std::process::ExitStatus;

        use crate::subprocess::{CapturedStream, ContainmentEvidence};

        use super::*;

        #[test]
        fn nonzero_formatter_diagnostic_precedes_a_broken_stdin_pipe() {
            let output: SubprocessOutput = map_execution(Execution {
                completion: Completion::Exited(exit_status(23)),
                containment: ContainmentEvidence {
                    empty_process_set_proven: true,
                    completion_notification_observed: false,
                },
                stdin: StdinOutcome::Failed(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stdin closed",
                )),
                stdout: CaptureOutcome::Complete(CapturedStream {
                    bytes: Vec::new(),
                    truncated: false,
                }),
                stderr: CaptureOutcome::Complete(CapturedStream {
                    bytes: b"formatter rejected input".to_vec(),
                    truncated: false,
                }),
            })
            .expect("nonzero formatter result must retain its diagnostic");
            assert!(!output.success);
            assert_eq!(output.exit, 23);
            assert_eq!(output.stderr, "formatter rejected input");
        }

        #[test]
        fn successful_formatter_output_rejects_truncation() {
            let error: FormatError = map_execution(Execution {
                completion: Completion::Exited(exit_status(0)),
                containment: ContainmentEvidence {
                    empty_process_set_proven: true,
                    completion_notification_observed: false,
                },
                stdin: StdinOutcome::Delivered,
                stdout: CaptureOutcome::Complete(CapturedStream {
                    bytes: b"partial".to_vec(),
                    truncated: true,
                }),
                stderr: CaptureOutcome::Complete(CapturedStream {
                    bytes: Vec::new(),
                    truncated: false,
                }),
            })
            .expect_err("truncated formatter output must not be accepted");
            let FormatError::ToolFailed { stderr, .. } = error else {
                panic!("truncation returned the wrong formatter error");
            };
            assert!(stderr.contains("stdout capture exceeded"));
        }

        #[cfg(unix)]
        fn exit_status(code: i32) -> ExitStatus {
            use std::os::unix::process::ExitStatusExt as _;

            ExitStatus::from_raw(code << 8)
        }

        #[cfg(windows)]
        fn exit_status(code: i32) -> ExitStatus {
            use std::os::windows::process::ExitStatusExt as _;

            ExitStatus::from_raw(u32::try_from(code).unwrap_or_default())
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use crate::format::FormatError;

    #[must_use]
    pub(in crate::format) fn tool_available(binary: &'static str) -> bool {
        tracing::debug!(tool = binary, "external formatters unavailable on wasm32");
        false
    }

    pub(in crate::format) fn run_or_fail(
        binary: &'static str,
        _args: &[&str],
        _input: &str,
        _timeout_secs: u32,
    ) -> Result<String, FormatError> {
        tracing::debug!(
            tool = binary,
            "external formatter invocation unsupported on wasm32"
        );
        Err(FormatError::ToolMissing(binary))
    }
}
