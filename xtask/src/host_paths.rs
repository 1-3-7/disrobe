use std::collections::BTreeSet;
use std::path::Path;

use eyre::Result;

use crate::fileio::read_bytes_bounded;

pub(crate) const MAX_SCANNED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ACCOUNT_NAME: usize = 64;
const WORKDIR: &[u8] = b"workdir";

pub(crate) const ALLOWED_HOMES: [(&str, &str); 26] = [
    (
        "corpus/beam/megafile/Elixir.EdgeCases.MyServer.beam",
        "home/runner",
    ),
    (
        "corpus/binfmt/appimage-type1/AppImageAssistant.AppImage",
        "home/travis",
    ),
    ("corpus/js/pkg/hello-pkg-tail.bin", "home/user"),
    ("corpus/shell/batch/megafile/edge_cases.bat", "Users/sample"),
    (
        "corpus/src/python/edge_cases/bytes_and_raw.py",
        "Users/name",
    ),
    ("crates/disrobe-binfmt/src/containers/eszip.rs", "Users/x"),
    ("crates/disrobe-binfmt/src/containers/eszip.rs", "home/user"),
    (
        "crates/disrobe-binfmt/tests/fixtures/rpm/rpm-v6-source.rpm",
        "home/dalley",
    ),
    ("crates/disrobe-core/src/recon/ioc.rs", "Users/dev"),
    ("crates/disrobe-core/tests/recon_scan.rs", "Users/victim"),
    ("crates/disrobe-llm-metadata/src/pii.rs", "home/alice"),
    ("crates/disrobe-pass-pyarmor/src/unpack.rs", "home/u"),
    (
        "crates/disrobe-pass-wasm-deob/src/dwarf/lines.rs",
        "home/user",
    ),
    ("crates/disrobe-pyarmor-cextract/src/capture.rs", "home/me"),
    (
        "crates/disrobe-pyarmor-cextract/src/capture.rs",
        "home/user",
    ),
    (
        "crates/disrobe-pyarmor-pytrace/tests/limits.rs",
        "Users/someone",
    ),
    (
        "crates/disrobe-pyarmor-pytrace/tests/limits.rs",
        "home/user",
    ),
    ("crates/disrobe-tool-process/src/windows.rs", "Users/tester"),
    ("playground/src/lib/samples.ts", "Users/Public"),
    ("xtask/src/host_paths.rs", "home/alice"),
    ("xtask/src/host_paths.rs", "Users/victim"),
    ("xtask/src/host_paths.rs", "Users/x"),
    ("xtask/src/host_paths.rs", "home/runner"),
    ("xtask/src/host_paths.rs", "Users/runner"),
    ("xtask/src/host_paths.rs", "Users/a_"),
    ("xtask/src/host_paths.rs", "workdir"),
];

#[derive(Debug, Default)]
pub(crate) struct HomeScan {
    pub(crate) unexpected: Vec<String>,
    pub(crate) stale_allowances: Vec<String>,
}

pub(crate) fn scan_homes(root: &Path, files: &BTreeSet<String>) -> Result<HomeScan> {
    let mut scan: HomeScan = HomeScan::default();
    let mut used: BTreeSet<(&str, String)> = BTreeSet::new();
    for file in files {
        let path: std::path::PathBuf = root.join(file);
        if !path.is_file() {
            continue;
        }
        let bytes: Vec<u8> = read_bytes_bounded(&path, MAX_SCANNED_BYTES)?;
        for home in home_directories(&bytes) {
            match ALLOWED_HOMES
                .iter()
                .find(|(allowed_file, allowed_home): &&(&str, &str)| {
                    *allowed_file == file && *allowed_home == home
                }) {
                Some((allowed_file, _)) => {
                    used.insert((allowed_file, home));
                }
                None => scan.unexpected.push(format!("{file}: {home}")),
            }
        }
    }
    for (file, home) in ALLOWED_HOMES {
        if !used.contains(&(file, home.to_owned())) {
            scan.stale_allowances.push(format!("{file}: {home}"));
        }
    }
    Ok(scan)
}

pub(crate) fn home_directories(bytes: &[u8]) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for (index, byte) in bytes.iter().enumerate() {
        if !is_separator(*byte)
            || index
                .checked_sub(1)
                .is_some_and(|before: usize| is_separator(bytes[before]))
        {
            continue;
        }
        let run: usize = separator_run(&bytes[index..]);
        if !starts_a_path(bytes, index) {
            continue;
        }
        let rest: &[u8] = &bytes[index + run..];
        if follows_a_drive(bytes, index)
            && rest.len() > WORKDIR.len()
            && rest[..WORKDIR.len()].eq_ignore_ascii_case(WORKDIR)
            && is_separator(rest[WORKDIR.len()])
        {
            found.insert("workdir".to_owned());
            continue;
        }
        let (kind, after): (&str, usize) =
            if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case(b"users") {
                ("Users", 5)
            } else if rest.starts_with(b"home") {
                ("home", 4)
            } else {
                continue;
            };
        let tail: &[u8] = &rest[after..];
        let gap: usize = separator_run(tail);
        if gap == 0 {
            continue;
        }
        let name: &[u8] = &tail[gap..];
        let length: usize = name
            .iter()
            .take_while(|byte: &&u8| is_account_byte(**byte))
            .count();
        if length == 0
            || length > MAX_ACCOUNT_NAME
            || !name.get(length).copied().is_some_and(is_separator)
        {
            continue;
        }
        let account: String = String::from_utf8_lossy(&name[..length]).into_owned();
        found.insert(format!("{kind}/{account}"));
    }
    found
}

fn follows_a_drive(bytes: &[u8], separator: usize) -> bool {
    separator.checked_sub(2).is_some_and(|drive: usize| {
        bytes[drive].is_ascii_alphabetic()
            && bytes[drive + 1] == b':'
            && drive
                .checked_sub(1)
                .is_none_or(|before: usize| !bytes[before].is_ascii_alphanumeric())
    })
}

fn starts_a_path(bytes: &[u8], separator: usize) -> bool {
    separator
        .checked_sub(1)
        .is_none_or(|before: usize| !is_account_byte(bytes[before]))
}

fn separator_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take(3)
        .take_while(|byte: &&u8| is_separator(**byte))
        .count()
}

const fn is_separator(byte: u8) -> bool {
    byte == b'/' || byte == b'\\'
}

const fn is_account_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'$')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn homes(text: &str) -> Vec<String> {
        home_directories(text.as_bytes()).into_iter().collect()
    }

    #[test]
    fn every_home_spelling_is_found() {
        assert_eq!(homes(r"C:\Users\victim\AppData"), vec!["Users/victim"]);
        assert_eq!(homes(r#""C:\\Users\\x\\.cargo""#), vec!["Users/x"]);
        assert_eq!(homes("c:/users/runner/work"), vec!["Users/runner"]);
        assert_eq!(homes("file:///home/alice/.ssh"), vec!["home/alice"]);
        assert_eq!(homes("at /Users/a_/src"), vec!["Users/a_"]);
        assert_eq!(homes(r"@c:\workdir\Documents\x.lua"), vec!["workdir"]);
        assert_eq!(
            homes("file:///C:/workdir/AppData/Local/Temp/x"),
            vec!["workdir"]
        );
    }

    #[test]
    fn nested_or_neutral_paths_are_not_homes() {
        assert!(homes("/var/home/user/x /srv/Users/x/ /srv/workdir/x AC:/workdir/x").is_empty());
        assert!(homes("/home/ and /home/user without a separator /home/user").is_empty());
        assert!(homes("/usr/lib /homework/x/ C:\\Users\\").is_empty());
    }

    #[test]
    fn an_added_home_outside_the_allow_list_is_reported() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        std::fs::write(
            root.path().join("probe.txt"),
            b"built in /home/runner/work\n",
        )?;
        let files: BTreeSet<String> = BTreeSet::from(["probe.txt".to_owned()]);
        assert_eq!(
            scan_homes(root.path(), &files)?.unexpected,
            vec!["probe.txt: home/runner"]
        );
        Ok(())
    }
}
