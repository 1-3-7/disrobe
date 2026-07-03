use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use eyre::{Result, WrapErr, bail};

pub const MAX_FIXTURE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TREE_FILES: usize = 65_536;
pub const MAX_TREE_TEXT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ZIP_ENTRIES: usize = 16_384;
pub const MAX_ZIP_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_ZIP_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_PICKLE_FILES: usize = 65_536;
pub const MAX_PICKLE_DEPTH: usize = 64;

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

pub fn version_of(bin: &PathBuf, args: &[&str]) -> String {
    let Ok(out): std::result::Result<Output, _> = Command::new(bin).args(args).output() else {
        return "n/a".to_owned();
    };
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let text: String = if stdout.trim().is_empty() {
        stderr
    } else {
        stdout
    };
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
        .unwrap_or_else(|| "n/a".to_owned())
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

pub fn run(bin: &PathBuf, args: &[&str]) -> std::result::Result<Output, String> {
    Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| e.to_string())
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
}
