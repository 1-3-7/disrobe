use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("fixture path `{path}` must be a non-empty workspace-relative path")]
    InvalidPath { path: String },
    #[error("no workspace root containing Cargo.lock above `{start}`")]
    WorkspaceRoot { start: PathBuf },
    #[error("could not resolve workspace root `{root}`: {source}")]
    ResolveWorkspace {
        root: PathBuf,
        source: std::io::Error,
    },
    #[error("could not resolve fixture `{path}`: {source}")]
    Resolve {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("fixture `{path}` resolves outside workspace root `{root}`")]
    OutsideWorkspace { path: PathBuf, root: PathBuf },
    #[error("could not inspect fixture `{path}`: {source}")]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("fixture `{path}` is not a regular file")]
    NotFile { path: PathBuf },
    #[error("fixture `{path}` exceeds the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("fixture `{path}` cannot fit in this process address space")]
    AddressSpace { path: PathBuf },
    #[error("could not read fixture `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub fn load_fixture(relative_path: &str, max_bytes: u64) -> Result<Vec<u8>, FixtureError> {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root: PathBuf = manifest
        .ancestors()
        .find(|directory: &&Path| directory.join("Cargo.lock").is_file())
        .map(Path::to_path_buf)
        .ok_or_else(|| FixtureError::WorkspaceRoot {
            start: manifest.to_path_buf(),
        })?;
    load_from_root(&root, relative_path, max_bytes)
}

fn load_from_root(
    workspace_root: &Path,
    relative_path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, FixtureError> {
    let normalized: PathBuf = normalize_path(relative_path)?;
    let root: PathBuf = fs::canonicalize(workspace_root).map_err(|source: std::io::Error| {
        FixtureError::ResolveWorkspace {
            root: workspace_root.to_path_buf(),
            source,
        }
    })?;
    let candidate: PathBuf = root.join(normalized);
    let resolved: PathBuf =
        fs::canonicalize(&candidate).map_err(|source: std::io::Error| FixtureError::Resolve {
            path: candidate.clone(),
            source,
        })?;
    if !resolved.starts_with(&root) {
        return Err(FixtureError::OutsideWorkspace {
            path: resolved,
            root,
        });
    }
    let metadata: fs::Metadata =
        fs::metadata(&resolved).map_err(|source: std::io::Error| FixtureError::Metadata {
            path: resolved.clone(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(FixtureError::NotFile { path: resolved });
    }
    if metadata.len() > max_bytes {
        return Err(FixtureError::TooLarge {
            path: resolved,
            limit: max_bytes,
        });
    }
    let capacity: usize =
        usize::try_from(metadata.len()).map_err(|_| FixtureError::AddressSpace {
            path: resolved.clone(),
        })?;
    let file: fs::File =
        fs::File::open(&resolved).map_err(|source: std::io::Error| FixtureError::Read {
            path: resolved.clone(),
            source,
        })?;
    let mut reader: std::io::Take<fs::File> = file.take(max_bytes.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    reader
        .read_to_end(&mut bytes)
        .map_err(|source: std::io::Error| FixtureError::Read {
            path: resolved.clone(),
            source,
        })?;
    let actual_size: u64 = u64::try_from(bytes.len()).map_err(|_| FixtureError::AddressSpace {
        path: resolved.clone(),
    })?;
    if actual_size > max_bytes {
        return Err(FixtureError::TooLarge {
            path: resolved,
            limit: max_bytes,
        });
    }
    Ok(bytes)
}

fn normalize_path(path: &str) -> Result<PathBuf, FixtureError> {
    let input: PathBuf = PathBuf::from(path);
    if path.is_empty() || path.contains(':') || input.is_absolute() {
        return Err(FixtureError::InvalidPath {
            path: path.to_owned(),
        });
    }
    let mut normalized: PathBuf = PathBuf::new();
    for component in input.components() {
        let Component::Normal(part) = component else {
            return Err(FixtureError::InvalidPath {
                path: path.to_owned(),
            });
        };
        normalized.push(part);
    }
    if normalized.as_os_str().is_empty() {
        return Err(FixtureError::InvalidPath {
            path: path.to_owned(),
        });
    }
    Ok(normalized)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{FixtureError, load_from_root};

    #[test]
    fn reads_an_existing_relative_fixture_within_the_supplied_limit() -> Result<(), String> {
        let root: tempfile::TempDir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let fixtures: std::path::PathBuf = root.path().join("fixtures");
        std::fs::create_dir(&fixtures).map_err(|error| error.to_string())?;
        std::fs::write(fixtures.join("sample.bin"), [1_u8, 2, 3])
            .map_err(|error| error.to_string())?;

        let bytes: Vec<u8> = load_from_root(root.path(), "fixtures/sample.bin", 3)
            .map_err(|error| error.to_string())?;
        assert_eq!(bytes, [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn rejects_absolute_and_parent_fixture_paths() {
        for path in ["../fixture.bin", "/fixture.bin", "C:\\fixture.bin"] {
            assert!(matches!(
                load_from_root(std::path::Path::new("."), path, 1),
                Err(FixtureError::InvalidPath { .. })
            ));
        }
    }

    #[test]
    fn rejects_a_fixture_before_reading_past_the_supplied_limit() -> Result<(), String> {
        let root: tempfile::TempDir = tempfile::tempdir().map_err(|error| error.to_string())?;
        std::fs::write(root.path().join("fixture.bin"), [1_u8, 2, 3])
            .map_err(|error| error.to_string())?;

        let error: FixtureError = load_from_root(root.path(), "fixture.bin", 2)
            .expect_err("oversized fixture must be refused");
        assert!(matches!(error, FixtureError::TooLarge { limit: 2, .. }));
        Ok(())
    }
}
