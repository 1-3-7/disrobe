use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAX_BACKEND_CAPTURE: usize = 4 * 1024 * 1024;
const CAPTURE_READ_CHUNK: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JvmBackend {
    Cfr,
    Vineflower,
    Procyon,
    JdGui,
    Krakatau,
}

impl JvmBackend {
    #[inline]
    #[must_use]
    pub const fn cli_token(self) -> &'static str {
        match self {
            Self::Cfr => "cfr",
            Self::Vineflower => "vineflower",
            Self::Procyon => "procyon",
            Self::JdGui => "jd",
            Self::Krakatau => "krakatau",
        }
    }

    #[inline]
    #[must_use]
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Cfr => "cfr",
            Self::Vineflower => "vineflower",
            Self::Procyon => "procyon",
            Self::JdGui => "jd-cli",
            Self::Krakatau => "krakatau2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AndroidBackend {
    Jadx,
    Dex2Jar,
}

impl AndroidBackend {
    #[inline]
    #[must_use]
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Jadx => "jadx",
            Self::Dex2Jar => "d2j-dex2jar",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapability {
    pub jvm: Vec<JvmBackend>,
    pub android: Vec<AndroidBackend>,
}

#[must_use]
pub fn detect_available() -> BackendCapability {
    let mut jvm: Vec<JvmBackend> = Vec::new();
    for b in [
        JvmBackend::Cfr,
        JvmBackend::Vineflower,
        JvmBackend::Procyon,
        JvmBackend::JdGui,
        JvmBackend::Krakatau,
    ] {
        if which_exists(b.binary_name()).is_some() {
            jvm.push(b);
        }
    }
    let mut android: Vec<AndroidBackend> = Vec::new();
    for b in [AndroidBackend::Jadx, AndroidBackend::Dex2Jar] {
        if which_exists(b.binary_name()).is_some() {
            android.push(b);
        }
    }
    BackendCapability { jvm, android }
}

fn which_exists(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for ext in possible_extensions() {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
const fn possible_extensions() -> &'static [&'static str] {
    &[".exe", ".bat", ".cmd", ""]
}

#[cfg(not(windows))]
const fn possible_extensions() -> &'static [&'static str] {
    &[""]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInvocation {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

fn read_capped_output<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let read: usize = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining: usize = MAX_BACKEND_CAPTURE.saturating_sub(out.len());
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
    label: &str,
    stream: &str,
) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| Error::BackendFailed {
            tool: label.to_string(),
            status: -1,
            stderr: format!("{stream} reader panicked"),
        })?
        .map_err(|e: std::io::Error| Error::BackendFailed {
            tool: label.to_string(),
            status: -1,
            stderr: format!("{stream} read failed: {e}"),
        })
}

pub fn invoke_jvm(
    backend: JvmBackend,
    args: &[String],
    timeout: Duration,
) -> Result<BackendInvocation> {
    let binary: &'static str = backend.binary_name();
    let path: PathBuf = which_exists(binary)
        .ok_or_else(|| Error::MissingTool(format!("{} ({})", backend.cli_token(), binary)))?;
    spawn_with_timeout(path, args, timeout, backend.cli_token())
}

pub fn invoke_android(
    backend: AndroidBackend,
    args: &[String],
    timeout: Duration,
) -> Result<BackendInvocation> {
    let binary: &'static str = backend.binary_name();
    let path: PathBuf =
        which_exists(binary).ok_or_else(|| Error::MissingTool(binary.to_string()))?;
    spawn_with_timeout(path, args, timeout, binary)
}

fn spawn_with_timeout(
    path: PathBuf,
    args: &[String],
    timeout: Duration,
    label: &str,
) -> Result<BackendInvocation> {
    let mut cmd: Command = Command::new(path);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child: std::process::Child = cmd.spawn()?;
    let stdout_reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>> =
        spawn_capture_reader(child.stdout.take());
    let stderr_reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>> =
        spawn_capture_reader(child.stderr.take());
    let status_opt: Option<std::process::ExitStatus> =
        wait_timeout::ChildExt::wait_timeout(&mut child, timeout).map_err(|e| {
            Error::BackendFailed {
                tool: label.to_string(),
                status: -1,
                stderr: e.to_string(),
            }
        })?;
    let status: std::process::ExitStatus = match status_opt {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            drop(join_capture_reader(stdout_reader, label, "stdout")?);
            drop(join_capture_reader(stderr_reader, label, "stderr")?);
            return Err(Error::BackendTimeout(
                label.to_string(),
                timeout.as_millis() as u64,
            ));
        }
    };
    let stdout: Vec<u8> = join_capture_reader(stdout_reader, label, "stdout")?;
    let stderr: Vec<u8> = join_capture_reader(stderr_reader, label, "stderr")?;
    let exit_code: i32 = status.code().unwrap_or(-1);
    if !status.success() {
        return Err(Error::BackendFailed {
            tool: label.to_string(),
            status: exit_code,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        });
    }
    Ok(BackendInvocation {
        stdout,
        stderr,
        exit_code,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_available_does_not_panic() {
        let caps: BackendCapability = detect_available();
        let _ = caps.jvm.len();
        let _ = caps.android.len();
    }

    #[test]
    fn missing_tool_error_when_absent() {
        let err: Error = invoke_jvm(JvmBackend::Krakatau, &[], Duration::from_millis(50))
            .expect_err("krakatau likely not installed in CI");
        assert!(matches!(
            err,
            Error::MissingTool(_)
                | Error::BackendFailed { .. }
                | Error::BackendTimeout(_, _)
                | Error::Io(_)
        ));
    }

    #[test]
    fn backend_capture_reader_stores_fixed_limit() -> std::io::Result<()> {
        let payload: Vec<u8> = vec![b'j'; MAX_BACKEND_CAPTURE + 1024];
        let captured: Vec<u8> = read_capped_output(std::io::Cursor::new(payload))?;
        assert_eq!(captured.len(), MAX_BACKEND_CAPTURE);
        assert!(captured.iter().all(|byte: &u8| *byte == b'j'));
        Ok(())
    }
}
