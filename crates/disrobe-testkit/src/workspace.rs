use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::TempDir;

use crate::error::{StressError, io_error};
use crate::rng::splitmix64;

static WORKSPACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct Workspace {
    directory: TempDir,
    pub(crate) token: u64,
}

impl Workspace {
    pub(crate) fn create() -> Result<Self, StressError> {
        let token: u64 = fresh_token();
        let directory: TempDir = tempfile::Builder::new()
            .prefix(&workspace_prefix(token))
            .tempdir()
            .map_err(|error: std::io::Error| {
                io_error("creating a unique stress workspace", error)
            })?;
        Ok(Self { directory, token })
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn retain(self) -> PathBuf {
        self.directory.keep()
    }
}

fn workspace_prefix(token: u64) -> String {
    format!("disrobe-stress-{}-{token:016x}-", std::process::id())
}

fn fresh_token() -> u64 {
    let mut hasher: std::hash::DefaultHasher = RandomState::new().build_hasher();
    hasher.write_u64(u64::from(std::process::id()));
    hasher.write_u64(WORKSPACE_SEQUENCE.fetch_add(1, Ordering::Relaxed));
    splitmix64(hasher.finish())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{Workspace, fresh_token, workspace_prefix};

    #[test]
    fn tokens_differ_between_calls() {
        assert_ne!(fresh_token(), fresh_token());
    }

    #[test]
    fn a_workspace_is_removed_unless_it_is_retained() {
        let path: std::path::PathBuf = {
            let workspace: Workspace = Workspace::create().expect("a temp workspace is creatable");
            assert!(workspace.path().is_dir());
            workspace.path().to_path_buf()
        };
        assert!(!path.exists(), "{} outlived its guard", path.display());
    }

    #[test]
    fn a_retained_workspace_survives_its_guard() {
        let workspace: Workspace = Workspace::create().expect("a temp workspace is creatable");
        let path: std::path::PathBuf = workspace.retain();
        assert!(path.is_dir(), "{} was not retained", path.display());
        std::fs::remove_dir_all(&path).expect("the retained workspace is removable");
    }

    #[test]
    fn the_directory_name_carries_the_pid_and_the_token() {
        let workspace: Workspace = Workspace::create().expect("a temp workspace is creatable");
        let name: String = workspace
            .path()
            .file_name()
            .map(|name: &std::ffi::OsStr| name.to_string_lossy().into_owned())
            .expect("the workspace has a file name");
        assert!(
            name.starts_with(&workspace_prefix(workspace.token)),
            "{name} does not carry the pid and token"
        );
    }
}
