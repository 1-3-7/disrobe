use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured, run_captured_with_env};
use eyre::{Result, WrapErr, bail};
use serde_json::{Value, json};

use crate::apkleaks_capture::sha256_hex;

pub const MAX_FIXTURE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TREE_FILES: usize = 65_536;
pub const MAX_TREE_TEXT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ZIP_ENTRIES: usize = 16_384;
pub const MAX_ZIP_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_ZIP_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_PICKLE_FILES: usize = 65_536;
pub const MAX_PICKLE_DEPTH: usize = 64;
pub const TOOL_TIMEOUT: Duration = Duration::from_mins(2);
pub const MAX_TOOL_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOOL_ERROR_BYTES: usize = 8 * 1024;

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".bat", ".cmd", ""]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn version_of(bin: &Path, args: &[&str]) -> String {
    version_of_checked(bin, args).unwrap_or_else(|_| "n/a".to_owned())
}

pub fn version_of_checked(bin: &Path, args: &[&str]) -> std::result::Result<String, String> {
    version_capture_checked(bin, args, None).map(|capture: VersionCapture| capture.display)
}

pub fn version_of_usage_checked(
    bin: &Path,
    args: &[&str],
    usage_exit_code: i32,
) -> std::result::Result<String, String> {
    version_capture_checked(bin, args, Some(usage_exit_code))
        .map(|capture: VersionCapture| capture.display)
}

pub fn version_of_usage(bin: &Path, args: &[&str], usage_exit_code: i32) -> String {
    let Ok(version): std::result::Result<String, String> =
        version_of_usage_checked(bin, args, usage_exit_code)
    else {
        return "n/a".to_owned();
    };
    version
}

#[derive(Debug)]
pub struct VersionCapture {
    pub display: String,
    pub output: CapturedOutput,
}

pub fn version_capture_checked(
    bin: &Path,
    args: &[&str],
    usage_exit_code: Option<i32>,
) -> std::result::Result<VersionCapture, String> {
    let output: CapturedOutput = run(bin, args)?;
    let display: String = version_from_output(&output, usage_exit_code)?;
    Ok(VersionCapture { display, output })
}

pub fn version_capture_with_env_checked(
    bin: &Path,
    args: &[&str],
    environment: &[(&str, &str)],
    usage_exit_code: Option<i32>,
) -> std::result::Result<VersionCapture, String> {
    let output: CapturedOutput = run_with_env(bin, args, environment)?;
    let display: String = version_from_output(&output, usage_exit_code)?;
    Ok(VersionCapture { display, output })
}

fn version_from_output(
    output: &CapturedOutput,
    usage_exit_code: Option<i32>,
) -> std::result::Result<String, String> {
    let accepted: bool = output
        .exit_code
        .is_some_and(|code: i32| code == 0 || usage_exit_code == Some(code));
    if !accepted {
        return Err(require_success_error(output, "version probe"));
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    let text: String = format!("{stdout}\n{stderr}");
    let cleaned: Vec<String> = text
        .lines()
        .map(strip_ansi)
        .map(|l: String| l.trim().to_owned())
        .filter(|l: &String| !l.is_empty())
        .collect();
    cleaned
        .iter()
        .find(|l: &&String| {
            l.chars().any(|c: char| c.is_ascii_digit())
                && l.chars().any(|c: char| c == '.')
                && l.len() < 64
        })
        .or_else(|| cleaned.first())
        .cloned()
        .ok_or_else(|| "version probe produced no text".to_owned())
}

fn require_success_error(output: &CapturedOutput, tool: &str) -> String {
    let detail: String = bounded_error_detail(&output.stderr);
    let detail: &str = if detail.is_empty() {
        "no stderr"
    } else {
        detail.as_str()
    };
    format!(
        "{tool} exited with {}: {detail}",
        output
            .exit_code
            .map_or_else(|| "no exit code".to_owned(), |code: i32| code.to_string())
    )
}

pub fn require_success(
    output: CapturedOutput,
    tool: &str,
) -> std::result::Result<CapturedOutput, String> {
    if output.exit_code == Some(0) {
        return Ok(output);
    }
    Err(require_success_error(&output, tool))
}

#[derive(Debug)]
pub struct ToolInvocation<'a> {
    pub route: &'a str,
    pub executable: &'a Path,
    pub args: &'a [String],
    pub environment: &'a [(&'a str, &'a str)],
    pub output: Option<&'a CapturedOutput>,
}

pub fn retain_tool_provenance(
    artifact_dir: &Path,
    invocation: &ToolInvocation<'_>,
    version_args: &[&str],
    version: &VersionCapture,
    input_hashes: &[(String, String)],
) -> std::result::Result<(), String> {
    let executable_bytes: Vec<u8> = read_bounded_file(invocation.executable, MAX_FIXTURE_BYTES)
        .map_err(|error| format!("hashing {}: {error}", invocation.executable.display()))?;
    std::fs::write(
        artifact_dir.join("version.stdout.bin"),
        &version.output.stdout,
    )
    .map_err(|error| format!("retaining version stdout: {error}"))?;
    std::fs::write(
        artifact_dir.join("version.stderr.bin"),
        &version.output.stderr,
    )
    .map_err(|error| format!("retaining version stderr: {error}"))?;
    if let Some(output) = invocation.output {
        std::fs::write(artifact_dir.join("stdout.bin"), &output.stdout)
            .map_err(|error| format!("retaining invocation stdout: {error}"))?;
        std::fs::write(artifact_dir.join("stderr.bin"), &output.stderr)
            .map_err(|error| format!("retaining invocation stderr: {error}"))?;
    }
    let banner: String = [
        String::from_utf8_lossy(&version.output.stdout).into_owned(),
        String::from_utf8_lossy(&version.output.stderr).into_owned(),
    ]
    .into_iter()
    .filter(|stream: &String| !stream.is_empty())
    .collect();
    let inputs: Vec<Value> = input_hashes
        .iter()
        .map(|(name, digest): &(String, String)| json!({"name": name, "sha256": digest}))
        .collect();
    let environment: BTreeMap<&str, &str> = invocation.environment.iter().copied().collect();
    let mut provenance: Value = json!({
        "executable": invocation.executable.to_string_lossy(),
        "executable_sha256": sha256_hex(&executable_bytes),
        "execution_route": invocation.route,
        "version_args": version_args,
        "version_display": version.display.as_str(),
        "version_banner": banner,
        "version_stdout_sha256": sha256_hex(&version.output.stdout),
        "version_stderr_sha256": sha256_hex(&version.output.stderr),
        "inputs": inputs,
        "invocation_args": invocation.args,
        "environment_overrides": environment,
        "invocation_sha256": argument_list_sha256(invocation.args),
    });
    if let Some(output) = invocation.output {
        provenance["exit_code"] = json!(output.exit_code);
        provenance["stdout_sha256"] = json!(sha256_hex(&output.stdout));
        provenance["stderr_sha256"] = json!(sha256_hex(&output.stderr));
    }
    let mut raw: String = serde_json::to_string_pretty(&provenance)
        .map_err(|error| format!("serializing tool provenance: {error}"))?;
    raw.push('\n');
    std::fs::write(artifact_dir.join("provenance.json"), raw)
        .map_err(|error| format!("retaining tool provenance: {error}"))
}

fn argument_list_sha256(arguments: &[String]) -> String {
    let mut canonical: Vec<u8> = Vec::new();
    for argument in arguments {
        canonical.extend_from_slice(&(argument.len() as u64).to_le_bytes());
        canonical.extend_from_slice(argument.as_bytes());
    }
    sha256_hex(&canonical)
}

pub fn retain_source_tree(
    artifact_dir: &Path,
    sources: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<(), String> {
    let source_root: PathBuf = artifact_dir.join("sources");
    std::fs::create_dir(&source_root)
        .map_err(|error| format!("creating retained source root: {error}"))?;
    for (name, source) in sources {
        let relative: &Path = Path::new(name);
        if name.is_empty()
            || name.split(['/', '\\']).any(|component: &str| {
                component.is_empty() || matches!(component, "." | "..") || component.contains(':')
            })
            || relative
                .components()
                .any(|component: std::path::Component<'_>| {
                    !matches!(component, std::path::Component::Normal(_))
                })
        {
            return Err(format!("retained source path is unsafe: {name}"));
        }
        let path: PathBuf = source_root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("creating retained source directory: {error}"))?;
        }
        let mut options: std::fs::OpenOptions = std::fs::OpenOptions::new();
        let mut file: std::fs::File = options
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("creating retained source {}: {error}", path.display()))?;
        std::io::Write::write_all(&mut file, source.as_bytes())
            .map_err(|error| format!("writing retained source {}: {error}", path.display()))?;
    }
    Ok(())
}

fn bounded_error_detail(bytes: &[u8]) -> String {
    let end: usize = bytes.len().min(MAX_TOOL_ERROR_BYTES);
    let mut detail: String = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if bytes.len() > end {
        detail.push_str(" [stderr truncated]");
    }
    detail
}

pub fn bounded_error_text(text: &str) -> String {
    bounded_error_detail(text.as_bytes())
}

fn strip_ansi(line: &str) -> String {
    let mut out: String = String::with_capacity(line.len());
    let mut chars: std::str::Chars<'_> = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for nc in chars.by_ref() {
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn run<S: AsRef<OsStr>>(bin: &Path, args: &[S]) -> std::result::Result<CapturedOutput, String> {
    run_captured(bin, args, TOOL_TIMEOUT, MAX_TOOL_CAPTURE_BYTES)
        .map_err(|error: std::io::Error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "tool exceeded the {} second execution limit",
                TOOL_TIMEOUT.as_secs()
            )
        })
}

pub fn run_with_env<S: AsRef<OsStr>>(
    bin: &Path,
    args: &[S],
    env: &[(&str, &str)],
) -> std::result::Result<CapturedOutput, String> {
    let environment: Vec<(OsString, OsString)> = env
        .iter()
        .map(|(key, value): &(&str, &str)| (OsString::from(*key), OsString::from(*value)))
        .collect();
    run_captured_with_env(bin, args, environment, TOOL_TIMEOUT, MAX_TOOL_CAPTURE_BYTES)
        .map_err(|error: std::io::Error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "tool exceeded the {} second execution limit",
                TOOL_TIMEOUT.as_secs()
            )
        })
}

pub fn require_pinned_version(
    root: &Path,
    tool: &str,
    actual: &str,
) -> std::result::Result<(), String> {
    let path: PathBuf = authoritative_version_lock(root);
    let expected: String = pinned_version_value(&path, tool)?;
    let matches: bool = actual
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '.')
        .any(|token: &str| {
            token == expected
                || token
                    .strip_prefix('v')
                    .or_else(|| token.strip_prefix('V'))
                    .is_some_and(|version: &str| version == expected)
        });
    if matches {
        Ok(())
    } else {
        Err(format!(
            "{tool} reports {actual}, but {} pins {expected}",
            path.display()
        ))
    }
}

pub fn require_pinned_token(
    root: &Path,
    key: &str,
    actual: &str,
) -> std::result::Result<(), String> {
    let path: PathBuf = authoritative_version_lock(root);
    let expected: String = pinned_version_value(&path, key)?;
    let matches: bool = actual
        .split(|character: char| {
            !character.is_ascii_alphanumeric() && !matches!(character, '.' | '+' | '-' | '_')
        })
        .any(|token: &str| token == expected);
    if matches {
        Ok(())
    } else {
        Err(format!(
            "{key} output does not contain the complete version token {expected}, as pinned by {}",
            path.display()
        ))
    }
}

fn authoritative_version_lock(root: &Path) -> PathBuf {
    root.join("evidence")
        .join("competitors")
        .join("versions.lock")
}

fn pinned_version_value(path: &Path, key: &str) -> std::result::Result<String, String> {
    let raw: String =
        read_bounded_string(path, MAX_TEXT_BYTES).map_err(|error| error.to_string())?;
    let values: BTreeMap<String, String> = toml::from_str(&raw)
        .map_err(|error| format!("{} is invalid TOML: {error}", path.display()))?;
    values
        .get(key)
        .cloned()
        .ok_or_else(|| format!("{key} has no pinned value in {}", path.display()))
}

pub fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata: std::fs::Metadata =
        std::fs::metadata(path).wrap_err_with(|| format!("stat {}", path.display()))?;
    if metadata.len() > limit {
        bail!("{} exceeds {limit} byte cap", path.display());
    }
    let file: std::fs::File =
        std::fs::File::open(path).wrap_err_with(|| format!("open {}", path.display()))?;
    let mut limited: std::io::Take<std::fs::File> = file.take(limit.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::new();
    let read_len: usize = limited
        .read_to_end(&mut bytes)
        .wrap_err_with(|| format!("read {}", path.display()))?;
    let read_len_u64: u64 = u64::try_from(read_len).unwrap_or(u64::MAX);
    if read_len_u64 > limit {
        bail!(
            "{} grew past {limit} byte cap while reading",
            path.display()
        );
    }
    Ok(bytes)
}

pub fn read_bounded_string(path: &Path, limit: u64) -> Result<String> {
    let bytes: Vec<u8> = read_bounded_file(path, limit)?;
    String::from_utf8(bytes).wrap_err_with(|| format!("{} is not UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("disrobe_h2h_tool_{}_{}", std::process::id(), name))
    }

    #[test]
    fn bounded_file_rejects_oversized_input() -> core::result::Result<(), String> {
        let path: PathBuf = temp_file("oversized.bin");
        std::fs::write(&path, b"abcdef").map_err(|e| e.to_string())?;
        let result: Result<Vec<u8>> = read_bounded_file(&path, 5);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "six bytes must exceed a five-byte cap");
        Ok(())
    }

    #[test]
    fn failed_tool_output_keeps_bounded_stderr_in_the_error() {
        let output: CapturedOutput = CapturedOutput {
            stdout: Vec::new(),
            stderr: b"cfr failed: malformed output".to_vec(),
            exit_code: Some(17),
        };
        let error: String = require_success(output, "cfr")
            .map_or_else(|error: String| error, |_| "unexpected success".to_owned());
        assert!(error.contains("cfr exited with 17"));
        assert!(error.contains("malformed output"));
    }

    #[test]
    fn bounded_error_text_keeps_prefix_and_caps_partial_output() {
        let text: String = "x".repeat(MAX_TOOL_ERROR_BYTES + 1);
        let bounded: String = bounded_error_text(&text);
        assert!(bounded.starts_with(&"x".repeat(MAX_TOOL_ERROR_BYTES)));
        assert!(bounded.ends_with(" [stderr truncated]"));
        assert!(bounded.len() <= MAX_TOOL_ERROR_BYTES + " [stderr truncated]".len());
    }

    #[test]
    fn pinned_version_requires_a_token_from_versions_lock() -> core::result::Result<(), String> {
        let root: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-h2h-version-lock")
                .map_err(|error: std::io::Error| error.to_string())?;
        let lock_dir: PathBuf = root.path().join("evidence").join("competitors");
        std::fs::create_dir_all(&lock_dir).map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(
            lock_dir.join("versions.lock"),
            b"jadx = \"1.5.5\"\napkleaks = \"2.6.3\"\n",
        )
        .map_err(|error: std::io::Error| error.to_string())?;
        require_pinned_version(root.path(), "jadx", "jadx version 1.5.5")?;
        require_pinned_version(root.path(), "apkleaks", "APKL v2.6.3")?;
        assert!(require_pinned_version(root.path(), "jadx", "jadx version 1.5.6").is_err());
        Ok(())
    }

    #[test]
    fn version_probe_accepts_a_named_usage_exit_when_the_version_is_present() {
        let output: CapturedOutput = CapturedOutput {
            stdout: Vec::new(),
            stderr: b"APKL v2.6.3\nusage: apkleaks -f FILE\n".to_vec(),
            exit_code: Some(2),
        };
        assert_eq!(
            version_from_output(&output, Some(2)),
            Ok("APKL v2.6.3".to_owned())
        );
    }

    #[test]
    fn version_probe_rejects_missing_exit_status() {
        let output: CapturedOutput = CapturedOutput {
            stdout: b"tool 1.2.3\n".to_vec(),
            stderr: Vec::new(),
            exit_code: None,
        };
        assert!(version_from_output(&output, None).is_err());
        assert!(version_from_output(&output, Some(2)).is_err());
    }

    #[test]
    fn retained_provenance_binds_executable_invocation_inputs_and_streams()
    -> core::result::Result<(), String> {
        let root: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-h2h-provenance")
                .map_err(|error| error.to_string())?;
        let executable: PathBuf = root.path().join("tool.bin");
        std::fs::write(&executable, b"tool-bytes").map_err(|error| error.to_string())?;
        let artifact_dir: PathBuf = root.path().join("artifacts");
        std::fs::create_dir(&artifact_dir).map_err(|error| error.to_string())?;
        let version: VersionCapture = VersionCapture {
            display: "tool 1.2.3".to_owned(),
            output: CapturedOutput {
                stdout: b"tool 1.2.3 full build 7\n".to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
            },
        };
        let invocation: CapturedOutput = CapturedOutput {
            stdout: b"result".to_vec(),
            stderr: b"detail".to_vec(),
            exit_code: Some(0),
        };
        let invocation_args: Vec<String> = vec!["--input".to_owned(), "fixture.bin".to_owned()];
        let environment: [(&str, &str); 2] =
            [("PATH", "selected-bin"), ("JAVA_HOME", "selected-jdk")];
        retain_tool_provenance(
            &artifact_dir,
            &ToolInvocation {
                route: "test-cli",
                executable: &executable,
                args: &invocation_args,
                environment: &environment,
                output: Some(&invocation),
            },
            &["--version"],
            &version,
            &[("fixture.bin".to_owned(), "11".repeat(32))],
        )?;
        let raw: String = std::fs::read_to_string(artifact_dir.join("provenance.json"))
            .map_err(|error| error.to_string())?;
        let value: Value = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
        assert_eq!(value["executable_sha256"], sha256_hex(b"tool-bytes"));
        assert_eq!(value["inputs"][0]["sha256"], "11".repeat(32));
        assert_eq!(value["environment_overrides"]["PATH"], "selected-bin");
        assert_eq!(value["environment_overrides"]["JAVA_HOME"], "selected-jdk");
        assert_eq!(
            value["environment_overrides"]
                .as_object()
                .map(serde_json::Map::len),
            Some(2)
        );
        assert!(value["invocation_sha256"].as_str().is_some());
        assert_eq!(
            std::fs::read(artifact_dir.join("stdout.bin")).map_err(|error| error.to_string())?,
            b"result"
        );
        Ok(())
    }

    #[test]
    fn pinned_build_requires_a_complete_version_token() -> core::result::Result<(), String> {
        let root: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-h2h-build-token")
                .map_err(|error| error.to_string())?;
        let versions: PathBuf = root.path().join("evidence").join("competitors");
        std::fs::create_dir_all(&versions).map_err(|error| error.to_string())?;
        std::fs::write(
            versions.join("versions.lock"),
            "# runtime\njava_build=\"25.0.4+7\" # build\n",
        )
        .map_err(|error| error.to_string())?;
        assert!(require_pinned_token(root.path(), "java_build", "build 25.0.4+7").is_ok());
        assert!(require_pinned_token(root.path(), "java_build", "build 25.0.4+70").is_err());
        Ok(())
    }
}
