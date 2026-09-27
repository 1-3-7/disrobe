use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use eyre::Result;
use sha2::{Digest, Sha256};

use crate::fileio::read_bytes_bounded;
use crate::host_paths::MAX_SCANNED_BYTES;

pub(crate) const PYARMOR_SERIAL_SHA256: &str =
    "674430c71478231b118b9218a3d4d5e622446ce3007ebb2b9df01e12215f8b99";
pub(crate) const PINNED_FILE_COUNT: usize = 34;
pub(crate) const PINNED_SET_SHA256: &str =
    "abcc44f9471dced1c43bc80f145961438cbc9c415af11951c42e04ef0143daab";
const SERIAL_DIGITS: usize = 6;
const MASK: &str = "<serial>";

#[derive(Debug)]
pub(crate) struct Footprint {
    pub(crate) files: BTreeSet<String>,
    pub(crate) set_sha256: String,
}

impl Footprint {
    pub(crate) fn masked_files(&self, serial_sha256: &str) -> Vec<String> {
        self.files
            .iter()
            .map(|file: &String| mask(file, serial_sha256))
            .collect()
    }
}

pub(crate) fn footprint(
    root: &Path,
    files: &BTreeSet<String>,
    serial_sha256: &str,
) -> Result<Footprint> {
    let mut matcher: SerialMatcher<'_> = SerialMatcher::new(serial_sha256);
    let mut found: BTreeSet<String> = BTreeSet::new();
    for file in files {
        if matcher.contains(file.as_bytes()) {
            found.insert(file.clone());
            continue;
        }
        let path: std::path::PathBuf = root.join(file);
        if !path.is_file() {
            continue;
        }
        let bytes: Vec<u8> = read_bytes_bounded(&path, MAX_SCANNED_BYTES)?;
        if matcher.contains(&bytes) {
            found.insert(file.clone());
        }
    }
    let listing: String = found.iter().cloned().collect::<Vec<String>>().join("\n");
    let set_sha256: String = sha256_hex(listing.as_bytes());
    Ok(Footprint {
        files: found,
        set_sha256,
    })
}

struct SerialMatcher<'a> {
    serial_sha256: &'a str,
    verdicts: BTreeMap<[u8; SERIAL_DIGITS], bool>,
}

impl<'a> SerialMatcher<'a> {
    const fn new(serial_sha256: &'a str) -> Self {
        Self {
            serial_sha256,
            verdicts: BTreeMap::new(),
        }
    }

    fn contains(&mut self, bytes: &[u8]) -> bool {
        digit_runs(bytes).any(|run: [u8; SERIAL_DIGITS]| {
            *self
                .verdicts
                .entry(run)
                .or_insert_with(|| sha256_hex(&run) == self.serial_sha256)
        })
    }
}

fn digit_runs(bytes: &[u8]) -> impl Iterator<Item = [u8; SERIAL_DIGITS]> + '_ {
    let mut index: usize = 0;
    std::iter::from_fn(move || {
        while index < bytes.len() {
            if !bytes[index].is_ascii_digit() {
                index += 1;
                continue;
            }
            let start: usize = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if let Ok(run) = <[u8; SERIAL_DIGITS]>::try_from(&bytes[start..index]) {
                return Some(run);
            }
        }
        None
    })
}

fn mask(text: &str, serial_sha256: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let mut masked: String = String::with_capacity(text.len());
    let mut index: usize = 0;
    while index < bytes.len() {
        let end: usize = index
            + bytes[index..]
                .iter()
                .take_while(|byte: &&u8| byte.is_ascii_digit())
                .count();
        if end > index {
            let run: &str = &text[index..end];
            if run.len() == SERIAL_DIGITS && sha256_hex(run.as_bytes()) == serial_sha256 {
                masked.push_str(MASK);
            } else {
                masked.push_str(run);
            }
            index = end;
        } else {
            let width: usize = text[index..].chars().next().map_or(1, char::len_utf8);
            masked.push_str(&text[index..index + width]);
            index += width;
        }
    }
    masked
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_serial() -> (String, String) {
        let serial: String = "314159".to_owned();
        let digest: String = sha256_hex(serial.as_bytes());
        (serial, digest)
    }

    #[test]
    fn only_a_standalone_six_digit_run_matches() {
        let (_, digest) = probe_serial();
        let mut matcher: SerialMatcher<'_> = SerialMatcher::new(&digest);
        assert!(matcher.contains(b"pyarmor_runtime_314159/__init__.py"));
        assert!(matcher.contains(b"b\"PY314159\""));
        assert!(!matcher.contains(b"3141592 and 031415 and 31415"));
        assert!(!matcher.contains(b"pyarmor_runtime_000000"));
    }

    #[test]
    fn a_probe_file_that_adds_the_serial_grows_the_footprint() -> Result<()> {
        let (serial, digest) = probe_serial();
        let root: tempfile::TempDir = tempfile::tempdir()?;
        std::fs::write(root.path().join("clean.txt"), b"pyarmor_runtime_000000\n")?;
        let clean: BTreeSet<String> = BTreeSet::from(["clean.txt".to_owned()]);
        assert!(footprint(root.path(), &clean, &digest)?.files.is_empty());

        let probe: String = format!("pyarmor_runtime_{serial}/probe.py");
        std::fs::create_dir_all(root.path().join(format!("pyarmor_runtime_{serial}")))?;
        std::fs::write(root.path().join(&probe), b"print(1)\n")?;
        std::fs::write(root.path().join("content.txt"), format!("key {serial}\n"))?;
        let grown: BTreeSet<String> =
            BTreeSet::from(["clean.txt".to_owned(), "content.txt".to_owned(), probe]);
        let found: Footprint = footprint(root.path(), &grown, &digest)?;
        assert_eq!(found.files.len(), 2);
        assert_eq!(
            found.masked_files(&digest),
            vec![
                "content.txt".to_owned(),
                "pyarmor_runtime_<serial>/probe.py".to_owned()
            ]
        );
        Ok(())
    }
}
