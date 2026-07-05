use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

const MAX_DIFF_FILE_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn read_bytes_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata: fs::Metadata =
        fs::metadata(path).wrap_err_with(|| format!("stat {}", path.display()))?;
    if metadata.len() > max_bytes {
        bail!("{} exceeds {max_bytes} byte cap", path.display());
    }
    let reserve: usize =
        usize::try_from(metadata.len().min(max_bytes)).map_or(0, |value: usize| value);
    let file: fs::File =
        fs::File::open(path).wrap_err_with(|| format!("open {}", path.display()))?;
    let mut reader: std::io::Take<fs::File> = file.take(max_bytes.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(reserve);
    reader
        .read_to_end(&mut bytes)
        .wrap_err_with(|| format!("read {}", path.display()))?;
    let len: u64 = u64::try_from(bytes.len()).map_or(u64::MAX, |value: u64| value);
    if len > max_bytes {
        bail!(
            "{} grew past {max_bytes} byte cap while reading",
            path.display()
        );
    }
    Ok(bytes)
}

pub(crate) fn read_text_bounded(path: &Path, max_bytes: u64) -> Result<String> {
    let bytes: Vec<u8> = read_bytes_bounded(path, max_bytes)?;
    String::from_utf8(bytes).wrap_err_with(|| format!("{} is not UTF-8", path.display()))
}

pub(crate) fn diff_generated_tree(
    expected_dir: &Path,
    committed_dir: &Path,
    stale: &mut Vec<String>,
) -> Result<()> {
    let mut expected_files: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    for entry in walkdir::WalkDir::new(expected_dir) {
        let dirent: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", expected_dir.display()))?;
        let path: &Path = dirent.path();
        if !path.is_file() {
            continue;
        }
        let rel: PathBuf = path
            .strip_prefix(expected_dir)
            .wrap_err_with(|| format!("stripping prefix from {}", path.display()))?
            .to_path_buf();
        let bytes: Vec<u8> = read_bytes_bounded(path, MAX_DIFF_FILE_BYTES)?;
        expected_files.insert(rel, bytes);
    }

    for (rel, expected_bytes) in &expected_files {
        let committed_path: PathBuf = committed_dir.join(rel);
        match read_bytes_bounded(&committed_path, MAX_DIFF_FILE_BYTES) {
            Ok(actual) if &actual == expected_bytes => {}
            Ok(_) => stale.push(format!(
                "{} differs from regenerated output",
                committed_path.display()
            )),
            Err(_) => stale.push(format!(
                "{} missing (regeneration would create it)",
                committed_path.display()
            )),
        }
    }

    if committed_dir.is_dir() {
        for entry in walkdir::WalkDir::new(committed_dir) {
            let dirent: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", committed_dir.display()))?;
            let path: &Path = dirent.path();
            if !path.is_file() {
                continue;
            }
            let rel: PathBuf = path
                .strip_prefix(committed_dir)
                .wrap_err_with(|| format!("stripping prefix from {}", path.display()))?
                .to_path_buf();
            if !expected_files.contains_key(&rel) {
                stale.push(format!(
                    "{} is orphaned; no longer produced by regeneration",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn diff_generated_flat(
    expected_dir: &Path,
    committed_dir: &Path,
    is_generated_name: fn(&str) -> bool,
    stale: &mut Vec<String>,
) -> Result<()> {
    let mut expected_names: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in fs::read_dir(expected_dir)
        .wrap_err_with(|| format!("reading {}", expected_dir.display()))?
    {
        let dirent: fs::DirEntry =
            entry.wrap_err_with(|| format!("reading entry in {}", expected_dir.display()))?;
        let path: PathBuf = dirent.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let bytes: Vec<u8> = read_bytes_bounded(&path, MAX_DIFF_FILE_BYTES)?;
        expected_names.insert(name.to_owned(), bytes);
    }

    for (name, expected_bytes) in &expected_names {
        let committed_path: PathBuf = committed_dir.join(name);
        match read_bytes_bounded(&committed_path, MAX_DIFF_FILE_BYTES) {
            Ok(actual) if &actual == expected_bytes => {}
            Ok(_) => stale.push(format!(
                "{} differs from regenerated output",
                committed_path.display()
            )),
            Err(_) => stale.push(format!(
                "{} missing (regeneration would create it)",
                committed_path.display()
            )),
        }
    }

    if committed_dir.is_dir() {
        for entry in fs::read_dir(committed_dir)
            .wrap_err_with(|| format!("reading {}", committed_dir.display()))?
        {
            let dirent: fs::DirEntry =
                entry.wrap_err_with(|| format!("reading entry in {}", committed_dir.display()))?;
            let path: PathBuf = dirent.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if is_generated_name(name) && !expected_names.contains_key(name) {
                stale.push(format!(
                    "{} is orphaned; no longer produced by regeneration",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn rejects_oversized_file_from_metadata() -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path: PathBuf = dir.path().join("oversized.txt");
        fs::write(&path, "abcdef").map_err(|e| e.to_string())?;
        let result: Result<String> = read_text_bounded(&path, 5);
        assert!(result.is_err(), "six bytes must exceed a five-byte cap");
        Ok(())
    }

    #[test]
    fn reads_utf8_at_cap() -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path: PathBuf = dir.path().join("bounded.txt");
        fs::write(&path, "abcde").map_err(|e| e.to_string())?;
        let result: String = read_text_bounded(&path, 5).map_err(|e| e.to_string())?;
        assert_eq!(result, "abcde");
        Ok(())
    }
}
