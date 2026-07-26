use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{StressError, io_error};
use crate::rng::splitmix64;

const WORKSPACE_ATTEMPTS: usize = 256;

static WORKSPACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct Workspace {
    pub(crate) path: PathBuf,
    pub(crate) token: u64,
    retain: bool,
}

impl Workspace {
    pub(crate) fn create() -> Result<Self, StressError> {
        let mut last: Option<std::io::Error> = None;
        for _ in 0..WORKSPACE_ATTEMPTS {
            let token: u64 = fresh_token();
            let path: PathBuf = std::env::temp_dir().join(format!(
                "disrobe-stress-{}-{token:016x}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        token,
                        retain: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    last = Some(error);
                }
                Err(error) => {
                    return Err(io_error(
                        format!("creating stress workspace {}", path.display()),
                        error,
                    ));
                }
            }
        }
        Err(io_error(
            "creating a unique stress workspace",
            last.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "every candidate workspace directory already existed",
                )
            }),
        ))
    }

    pub(crate) const fn retain(&mut self) {
        self.retain = true;
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.retain {
            let _: std::io::Result<()> = std::fs::remove_dir_all(&self.path);
        }
    }
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
    use super::{Workspace, fresh_token};

    #[test]
    fn tokens_differ_between_calls() {
        assert_ne!(fresh_token(), fresh_token());
    }

    #[test]
    fn a_workspace_is_removed_unless_it_is_retained() {
        let path: std::path::PathBuf = {
            let workspace: Workspace = Workspace::create().expect("a temp workspace is creatable");
            assert!(workspace.path.is_dir());
            workspace.path.clone()
        };
        assert!(!path.exists(), "{} outlived its guard", path.display());
    }

    #[test]
    fn a_retained_workspace_survives_its_guard() {
        let path: std::path::PathBuf = {
            let mut workspace: Workspace =
                Workspace::create().expect("a temp workspace is creatable");
            workspace.retain();
            workspace.path.clone()
        };
        assert!(path.is_dir(), "{} was not retained", path.display());
        std::fs::remove_dir_all(&path).expect("the retained workspace is removable");
    }

    #[test]
    fn the_directory_name_carries_the_pid_and_the_token() {
        let workspace: Workspace = Workspace::create().expect("a temp workspace is creatable");
        let name: String = workspace
            .path
            .file_name()
            .map(|name: &std::ffi::OsStr| name.to_string_lossy().into_owned())
            .expect("the workspace has a file name");
        assert_eq!(
            name,
            format!(
                "disrobe-stress-{}-{:016x}",
                std::process::id(),
                workspace.token
            )
        );
    }
}
