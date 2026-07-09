#[cfg(not(target_arch = "wasm32"))]
pub(super) use native::{run_or_fail, tool_available};

#[cfg(target_arch = "wasm32")]
pub(super) use wasm::{run_or_fail, tool_available};

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::{LazyLock, RwLock};
    use std::time::Duration;

    use crate::format::FormatError;
    use crate::subprocess::CapturedOutput;

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
        let mut cmd: Command = Command::new(resolved);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child: Child =
            cmd.spawn()
                .map_err(|e: std::io::Error| FormatError::ToolFailed {
                    stderr: e.to_string(),
                    exit: -1,
                })?;

        let stdin_opt: Option<std::process::ChildStdin> = child.stdin.take();
        let input_bytes: Vec<u8> = input.as_bytes().to_vec();
        let writer_handle: Option<std::thread::JoinHandle<()>> =
            stdin_opt.map(|mut stdin: std::process::ChildStdin| {
                std::thread::spawn(move || {
                    let _: std::io::Result<()> = stdin.write_all(&input_bytes);
                })
            });

        let timeout: Duration = Duration::from_secs(u64::from(timeout_secs));
        let captured: Option<CapturedOutput> =
            crate::subprocess::wait_with_output_timeout(child, timeout, MAX_CAPTURE_OUTPUT);
        if let Some(h) = writer_handle {
            let _: std::thread::Result<()> = h.join();
        }
        let Some(captured): Option<CapturedOutput> = captured else {
            return Err(FormatError::Timeout);
        };

        let exit: i32 = captured.exit_code.unwrap_or(-1);
        Ok(SubprocessOutput {
            stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
            exit,
            success: captured.exit_code == Some(0),
        })
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
