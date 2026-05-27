use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

use std::collections::BTreeMap;

use super::FormatError;

#[derive(Debug)]
pub(super) struct SubprocessOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit: i32,
    pub success: bool,
}

static AVAILABILITY_CACHE: LazyLock<RwLock<BTreeMap<&'static str, bool>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));

#[must_use]
pub(super) fn which_binary(binary: &'static str) -> Option<PathBuf> {
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
pub(super) fn tool_available(binary: &'static str) -> bool {
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

pub(super) fn run_formatter_stdio(
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
    let mut child: Child = cmd
        .spawn()
        .map_err(|e: std::io::Error| FormatError::ToolFailed {
            stderr: e.to_string(),
            exit: -1,
        })?;

    let stdin_opt: Option<std::process::ChildStdin> = child.stdin.take();
    let stdout_opt: Option<std::process::ChildStdout> = child.stdout.take();
    let stderr_opt: Option<std::process::ChildStderr> = child.stderr.take();

    let input_bytes: Vec<u8> = input.as_bytes().to_vec();
    let writer_handle: Option<std::thread::JoinHandle<()>> =
        stdin_opt.map(|mut stdin: std::process::ChildStdin| {
            std::thread::spawn(move || {
                let _: std::io::Result<()> = stdin.write_all(&input_bytes);
            })
        });
    let stdout_handle: Option<std::thread::JoinHandle<Vec<u8>>> =
        stdout_opt.map(|mut s: std::process::ChildStdout| {
            std::thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let _: std::io::Result<usize> = std::io::Read::read_to_end(&mut s, &mut buf);
                buf
            })
        });
    let stderr_handle: Option<std::thread::JoinHandle<Vec<u8>>> =
        stderr_opt.map(|mut s: std::process::ChildStderr| {
            std::thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let _: std::io::Result<usize> = std::io::Read::read_to_end(&mut s, &mut buf);
                buf
            })
        });

    let timeout: Duration = Duration::from_secs(u64::from(timeout_secs));
    let status_opt: Option<ExitStatus> = wait_timeout::ChildExt::wait_timeout(&mut child, timeout)
        .map_err(|e: std::io::Error| FormatError::ToolFailed {
            stderr: e.to_string(),
            exit: -1,
        })?;
    let Some(status): Option<ExitStatus> = status_opt else {
        let _: std::io::Result<()> = child.kill();
        let _: std::io::Result<ExitStatus> = child.wait();
        if let Some(h) = writer_handle {
            let _: std::thread::Result<()> = h.join();
        }
        if let Some(h) = stdout_handle {
            let _: std::thread::Result<Vec<u8>> = h.join();
        }
        if let Some(h) = stderr_handle {
            let _: std::thread::Result<Vec<u8>> = h.join();
        }
        return Err(FormatError::Timeout);
    };

    if let Some(h) = writer_handle {
        let _: std::thread::Result<()> = h.join();
    }
    let stdout: Vec<u8> = stdout_handle
        .and_then(|h: std::thread::JoinHandle<Vec<u8>>| h.join().ok())
        .unwrap_or_default();
    let stderr: Vec<u8> = stderr_handle
        .and_then(|h: std::thread::JoinHandle<Vec<u8>>| h.join().ok())
        .unwrap_or_default();

    let exit: i32 = status.code().unwrap_or(-1);
    Ok(SubprocessOutput {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit,
        success: status.success(),
    })
}

pub(super) fn run_or_fail(
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
