use std::fs;
use std::io::Read as _;
use std::path::Path;

use eyre::{Result, WrapErr, bail};

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
