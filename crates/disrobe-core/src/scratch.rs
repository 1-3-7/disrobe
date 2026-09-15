use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::time::now as sanctioned_now;

use crate::debug::DebugLog;

pub const SCRATCH_ROOT_NAME: &str = "disrobe-scratch";

const CREATE_ATTEMPTS: u32 = 256;
const REMOVE_ATTEMPTS: u32 = 5;
const REMOVE_BACKOFF_MS: u64 = 10;
const WINDOWS_SHARING_VIOLATION: i32 = 32;

static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn scratch_root() -> PathBuf {
    std::env::temp_dir().join(SCRATCH_ROOT_NAME)
}

fn fresh_token() -> u64 {
    let mut hasher: std::hash::DefaultHasher = RandomState::new().build_hasher();
    hasher.write_u64(u64::from(std::process::id()));
    hasher.write_u64(SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed));
    splitmix64(hasher.finish())
}

#[must_use]
pub const fn splitmix64(seed: u64) -> u64 {
    let mut z: u64 = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn is_transient(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::AlreadyExists
    ) {
        return true;
    }
    error.raw_os_error() == Some(WINDOWS_SHARING_VIOLATION)
}

fn remove_with_retry(path: &Path, directory: bool) -> io::Result<()> {
    let mut delay: u64 = REMOVE_BACKOFF_MS;
    let mut last: Option<io::Error> = None;
    for _ in 0..REMOVE_ATTEMPTS {
        let outcome: io::Result<()> = if directory {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) if is_transient(&error) => {
                last = Some(error);
                std::thread::sleep(Duration::from_millis(delay));
                delay = delay.saturating_mul(2);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::other(format!("could not remove scratch path {}", path.display()))
    }))
}

fn report_removal_failure(path: &Path, error: &io::Error) {
    DebugLog::for_scope("core.scratch")
        .kv("cleanup_failed", || format!("{}: {error}", path.display()));
}

#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
    closed: bool,
}

impl ScratchDir {
    pub fn create(purpose: &str) -> io::Result<Self> {
        let root: PathBuf = scratch_root();
        std::fs::create_dir_all(&root)?;
        let mut last: Option<io::Error> = None;
        for _ in 0..CREATE_ATTEMPTS {
            let candidate: PathBuf = root.join(format!(
                "{purpose}-{}-{:016x}",
                std::process::id(),
                fresh_token()
            ));
            match std::fs::create_dir(&candidate) {
                Ok(()) => {
                    return Ok(Self {
                        path: candidate,
                        closed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "every candidate scratch directory already existed",
            )
        }))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn close(mut self) -> io::Result<()> {
        self.closed = true;
        remove_with_retry(&self.path, true)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        if let Err(error) = remove_with_retry(&self.path, true) {
            report_removal_failure(&self.path, &error);
        }
    }
}

#[derive(Debug)]
pub struct ScratchFile {
    path: PathBuf,
    closed: bool,
}

impl ScratchFile {
    pub fn create(purpose: &str, extension: &str) -> io::Result<(Self, std::fs::File)> {
        let root: PathBuf = scratch_root();
        std::fs::create_dir_all(&root)?;
        let mut last: Option<io::Error> = None;
        for _ in 0..CREATE_ATTEMPTS {
            let name: String = if extension.is_empty() {
                format!("{purpose}-{}-{:016x}", std::process::id(), fresh_token())
            } else {
                format!(
                    "{purpose}-{}-{:016x}.{extension}",
                    std::process::id(),
                    fresh_token()
                )
            };
            let candidate: PathBuf = root.join(name);
            match std::fs::File::create_new(&candidate) {
                Ok(handle) => {
                    return Ok((
                        Self {
                            path: candidate,
                            closed: false,
                        },
                        handle,
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "every candidate scratch file already existed",
            )
        }))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn close(mut self) -> io::Result<()> {
        self.closed = true;
        remove_with_retry(&self.path, false)
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        if let Err(error) = remove_with_retry(&self.path, false) {
            report_removal_failure(&self.path, &error);
        }
    }
}

pub fn sweep_stale(older_than: Duration) -> io::Result<usize> {
    let root: PathBuf = scratch_root();
    let entries: std::fs::ReadDir = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let now: SystemTime = sanctioned_now();
    let mut swept: usize = 0;
    for entry in entries.flatten() {
        let Ok(metadata): io::Result<std::fs::Metadata> = entry.metadata() else {
            continue;
        };
        let Ok(modified): io::Result<SystemTime> = metadata.modified() else {
            continue;
        };
        let Ok(age): Result<Duration, std::time::SystemTimeError> = now.duration_since(modified)
        else {
            continue;
        };
        if age < older_than {
            continue;
        }
        let path: PathBuf = entry.path();
        if remove_with_retry(&path, metadata.is_dir()).is_ok() {
            swept = swept.saturating_add(1);
        }
    }
    Ok(swept)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_scratch_directory_lives_under_one_namespaced_root() {
        let dir: ScratchDir = ScratchDir::create("unit").expect("create");
        assert!(
            dir.path().starts_with(scratch_root()),
            "scratch must never sit loose in the temp root: {}",
            dir.path().display()
        );
        assert!(dir.path().is_dir());
    }

    #[test]
    fn dropping_a_scratch_directory_removes_it_and_its_contents() {
        let path: PathBuf = {
            let dir: ScratchDir = ScratchDir::create("unit-drop").expect("create");
            std::fs::write(dir.path().join("payload.bin"), b"content").expect("write");
            dir.path().to_path_buf()
        };
        assert!(
            !path.exists(),
            "the directory survived its guard: {}",
            path.display()
        );
    }

    #[test]
    fn closing_reports_success_and_leaves_nothing_behind() {
        let dir: ScratchDir = ScratchDir::create("unit-close").expect("create");
        let path: PathBuf = dir.path().to_path_buf();
        dir.close()
            .expect("close must succeed on a plain directory");
        assert!(!path.exists());
    }

    #[test]
    fn two_scratch_directories_never_collide() {
        let first: ScratchDir = ScratchDir::create("unit-unique").expect("first");
        let second: ScratchDir = ScratchDir::create("unit-unique").expect("second");
        assert_ne!(
            first.path(),
            second.path(),
            "the same name twice would let one run delete another's work"
        );
    }

    #[test]
    fn a_scratch_name_is_not_derivable_from_the_purpose_alone() {
        let first: ScratchDir = ScratchDir::create("unit-token").expect("first");
        let name: String = first
            .path()
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .expect("name")
            .to_owned();
        let prefix: String = format!("unit-token-{}-", std::process::id());
        assert!(name.starts_with(&prefix), "unexpected shape: {name}");
        let token: &str = &name[prefix.len()..];
        assert_eq!(token.len(), 16, "token must be a full 64 bits: {token}");
        assert!(token.chars().all(|c: char| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_scratch_file_is_created_exclusively_and_removed_on_drop() {
        let path: PathBuf = {
            let (file, mut handle): (ScratchFile, std::fs::File) =
                ScratchFile::create("unit-file", "bin").expect("create");
            std::io::Write::write_all(&mut handle, b"payload").expect("write");
            assert!(file.path().starts_with(scratch_root()));
            file.path().to_path_buf()
        };
        assert!(!path.exists(), "the file survived its guard");
    }

    #[test]
    fn a_removal_that_finds_nothing_is_success_not_an_error() {
        let missing: PathBuf = scratch_root().join("unit-absent-0000000000000000");
        remove_with_retry(&missing, true).expect("absence is the desired end state");
    }

    #[test]
    fn sweeping_leaves_fresh_scratch_alone() {
        let dir: ScratchDir = ScratchDir::create("unit-sweep").expect("create");
        let swept: usize = sweep_stale(Duration::from_hours(1)).expect("sweep");
        assert!(
            dir.path().is_dir(),
            "a sweep with a one hour cutoff must not touch a directory created just now"
        );
        let _ = swept;
    }
}
