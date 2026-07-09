use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAX_BACKEND_CAPTURE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Ilspy,
    Dnspy,
    DnspyEx,
    De4dot,
}

impl Backend {
    #[must_use]
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Ilspy => "ilspycmd",
            Self::Dnspy => "dnSpy",
            Self::DnspyEx => "dnSpyEx",
            Self::De4dot => "de4dot",
        }
    }

    #[must_use]
    pub const fn override_env(self) -> &'static str {
        match self {
            Self::Ilspy => "DISROBE_EXTERNAL_ILSPY",
            Self::Dnspy => "DISROBE_EXTERNAL_DNSPY",
            Self::DnspyEx => "DISROBE_EXTERNAL_DNSPYEX",
            Self::De4dot => "DISROBE_EXTERNAL_DE4DOT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInvocation {
    pub backend: Backend,
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

#[must_use]
pub fn probe(backend: Backend) -> bool {
    resolve_tool(backend).is_some()
}

pub fn invoke_decompile(
    backend: Backend,
    input: &Path,
    output_dir: &Path,
    timeout: Duration,
) -> Result<BackendInvocation> {
    let program: PathBuf =
        resolve_tool(backend).ok_or_else(|| Error::MissingTool(backend.binary_name()))?;
    std::fs::create_dir_all(output_dir)?;
    let input_s: String = input.to_string_lossy().into_owned();
    let out_s: String = output_dir.to_string_lossy().into_owned();
    let args: Vec<String> = match backend {
        Backend::Ilspy => vec!["-o".to_owned(), out_s, "--project".to_owned(), input_s],
        Backend::Dnspy | Backend::DnspyEx => vec![
            "--no-gui".to_owned(),
            "-o".to_owned(),
            out_s,
            "--project".to_owned(),
            input_s,
        ],
        Backend::De4dot => vec!["-r".to_owned(), out_s, input_s],
    };
    run_capture(backend, &program, &args, timeout)
}

fn resolve_tool(backend: Backend) -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os(backend.override_env()) {
        let p: PathBuf = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    which_on_path(backend.binary_name())
}

fn which_on_path(binary: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
            .split(';')
            .map(|s: &str| s.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in &exts {
            let candidate: PathBuf = if ext.is_empty() {
                dir.join(binary)
            } else {
                let mut name: std::ffi::OsString = binary.into();
                name.push(ext);
                dir.join(&name)
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn run_capture(
    backend: Backend,
    program: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<BackendInvocation> {
    let captured: Option<disrobe_core::subprocess::CapturedOutput> =
        disrobe_core::subprocess::run_captured(program, args, timeout, MAX_BACKEND_CAPTURE)?;
    let Some(captured): Option<disrobe_core::subprocess::CapturedOutput> = captured else {
        return Err(Error::BackendTimeout(
            backend.binary_name(),
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        ));
    };
    let code: i32 = captured.exit_code.unwrap_or(-1);
    let stdout_s: String = String::from_utf8_lossy(&captured.stdout).into_owned();
    let stderr_s: String = String::from_utf8_lossy(&captured.stderr).into_owned();
    if code != 0 {
        return Err(Error::BackendFailed {
            tool: backend.binary_name(),
            status: code,
            stderr: stderr_s,
        });
    }
    Ok(BackendInvocation {
        backend,
        stdout: stdout_s,
        stderr: stderr_s,
        status: code,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn backend_names_unique_per_variant() {
        let names: [&str; 4] = [
            Backend::Ilspy.binary_name(),
            Backend::Dnspy.binary_name(),
            Backend::DnspyEx.binary_name(),
            Backend::De4dot.binary_name(),
        ];
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    #[test]
    fn override_env_names_are_distinct() {
        let envs: [&str; 4] = [
            Backend::Ilspy.override_env(),
            Backend::Dnspy.override_env(),
            Backend::DnspyEx.override_env(),
            Backend::De4dot.override_env(),
        ];
        let mut sorted: Vec<&str> = envs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }
}
