use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const AUTHORED_SOURCES: &str = include_str!("../data/authored_sources.toml");
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AuthoredSourceError {
    #[error("authored source path `{path}` must be a non-empty normalized workspace-relative path")]
    InvalidPath { path: String },
    #[error("authored source manifest does not parse: {source}")]
    ManifestSyntax { source: toml::de::Error },
    #[error("authored source manifest path `{path}` is invalid")]
    ManifestPath { path: String },
    #[error("authored source manifest hash for `{path}` is not a lowercase SHA-256 digest")]
    ManifestHash { path: String },
    #[error("authored source manifest lists `{path}` more than once")]
    DuplicateManifestPath { path: String },
    #[error("`{path}` is not an authorized authored source")]
    Unlisted { path: String },
    #[error("could not resolve workspace root `{root}`: {source}")]
    WorkspaceRoot {
        root: PathBuf,
        source: std::io::Error,
    },
    #[error("could not inspect authorized source `{path}`: {source}")]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("authorized source `{path}` is not a regular file")]
    NotFile { path: PathBuf },
    #[error("authorized source `{path}` exceeds the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("could not read authorized source `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("authorized source `{path}` resolves outside workspace root `{root}`")]
    OutsideWorkspace { path: PathBuf, root: PathBuf },
    #[error("authorized source `{path}` hash drifted: expected {expected}, found {actual}")]
    HashDrift {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    source: Vec<SourceRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    path: String,
    sha256: String,
}

pub fn authorized_authored_source(
    workspace_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, AuthoredSourceError> {
    authorize_from_manifest(workspace_root, relative_path, AUTHORED_SOURCES)
}

fn authorize_from_manifest(
    workspace_root: &Path,
    relative_path: &str,
    manifest_text: &str,
) -> Result<PathBuf, AuthoredSourceError> {
    let normalized: String = normalize_path(relative_path)?;
    let sources: BTreeMap<String, String> = parse_manifest(manifest_text)?;
    let expected: String =
        sources
            .get(&normalized)
            .cloned()
            .ok_or_else(|| AuthoredSourceError::Unlisted {
                path: normalized.clone(),
            })?;
    let root: PathBuf = fs::canonicalize(workspace_root).map_err(|source: std::io::Error| {
        AuthoredSourceError::WorkspaceRoot {
            root: workspace_root.to_path_buf(),
            source,
        }
    })?;
    let candidate: PathBuf = root.join(&normalized);
    let resolved: PathBuf = fs::canonicalize(&candidate).map_err(|source: std::io::Error| {
        AuthoredSourceError::Metadata {
            path: candidate.clone(),
            source,
        }
    })?;
    if !resolved.starts_with(&root) {
        return Err(AuthoredSourceError::OutsideWorkspace {
            path: resolved,
            root,
        });
    }
    let metadata: fs::Metadata = fs::metadata(&resolved).map_err(|source: std::io::Error| {
        AuthoredSourceError::Metadata {
            path: resolved.clone(),
            source,
        }
    })?;
    if !metadata.is_file() {
        return Err(AuthoredSourceError::NotFile { path: resolved });
    }
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(AuthoredSourceError::TooLarge {
            path: resolved,
            limit: MAX_SOURCE_BYTES,
        });
    }
    let file: fs::File =
        fs::File::open(&resolved).map_err(|source: std::io::Error| AuthoredSourceError::Read {
            path: resolved.clone(),
            source,
        })?;
    let mut reader: std::io::Take<fs::File> = file.take(MAX_SOURCE_BYTES.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|source: std::io::Error| AuthoredSourceError::Read {
            path: resolved.clone(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SOURCE_BYTES {
        return Err(AuthoredSourceError::TooLarge {
            path: resolved,
            limit: MAX_SOURCE_BYTES,
        });
    }
    let actual: String = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(AuthoredSourceError::HashDrift {
            path: resolved,
            expected,
            actual,
        });
    }
    Ok(resolved)
}

fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, AuthoredSourceError> {
    let manifest: SourceManifest = toml::from_str(text)
        .map_err(|source: toml::de::Error| AuthoredSourceError::ManifestSyntax { source })?;
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for record in manifest.source {
        let path: String =
            normalize_path(&record.path).map_err(|_| AuthoredSourceError::ManifestPath {
                path: record.path.clone(),
            })?;
        if !is_sha256(&record.sha256) {
            return Err(AuthoredSourceError::ManifestHash { path });
        }
        if sources.insert(path.clone(), record.sha256).is_some() {
            return Err(AuthoredSourceError::DuplicateManifestPath { path });
        }
    }
    Ok(sources)
}

fn normalize_path(path: &str) -> Result<String, AuthoredSourceError> {
    let input: PathBuf = PathBuf::from(path);
    if path.is_empty() || path.contains(':') || input.is_absolute() {
        return Err(AuthoredSourceError::InvalidPath {
            path: path.to_owned(),
        });
    }
    let mut normalized: PathBuf = PathBuf::new();
    for component in input.components() {
        let Component::Normal(part) = component else {
            return Err(AuthoredSourceError::InvalidPath {
                path: path.to_owned(),
            });
        };
        normalized.push(part);
    }
    let normalized: String = normalized.to_string_lossy().replace('\\', "/");
    if normalized.is_empty() {
        return Err(AuthoredSourceError::InvalidPath {
            path: path.to_owned(),
        });
    }
    Ok(normalized)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{AuthoredSourceError, authorize_from_manifest};

    const MARKER: &[u8] = b"print('approved')\n";

    fn manifest(hash: &str) -> String {
        format!("[[source]]\npath = \"corpus/approved.py\"\nsha256 = \"{hash}\"\n")
    }

    fn sha256(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};

        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn an_unlisted_marker_path_is_rejected_before_it_can_be_launched() -> Result<(), String> {
        let root: tempfile::TempDir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let corpus: std::path::PathBuf = root.path().join("corpus");
        std::fs::create_dir(&corpus).map_err(|error| error.to_string())?;
        std::fs::write(corpus.join("approved.py"), MARKER).map_err(|error| error.to_string())?;
        std::fs::write(corpus.join("marker.py"), b"print('marker')\n")
            .map_err(|error| error.to_string())?;
        let error: AuthoredSourceError = match authorize_from_manifest(
            root.path(),
            "corpus/marker.py",
            &manifest(&sha256(MARKER)),
        ) {
            Err(error) => error,
            Ok(path) => {
                return Err(format!(
                    "unlisted marker was authorized as {}",
                    path.display()
                ));
            }
        };
        assert!(matches!(error, AuthoredSourceError::Unlisted { .. }));
        Ok(())
    }

    #[test]
    fn a_one_byte_source_drift_is_rejected() -> Result<(), String> {
        let root: tempfile::TempDir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let corpus: std::path::PathBuf = root.path().join("corpus");
        std::fs::create_dir(&corpus).map_err(|error| error.to_string())?;
        std::fs::write(corpus.join("approved.py"), b"print('approvee')\n")
            .map_err(|error| error.to_string())?;
        let error: AuthoredSourceError = match authorize_from_manifest(
            root.path(),
            "corpus/approved.py",
            &manifest(&sha256(MARKER)),
        ) {
            Err(error) => error,
            Ok(path) => {
                return Err(format!(
                    "drifted source was authorized as {}",
                    path.display()
                ));
            }
        };
        assert!(matches!(error, AuthoredSourceError::HashDrift { .. }));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_listed_symlink_outside_the_workspace_is_rejected() -> Result<(), String> {
        use std::os::unix::fs::symlink;

        let root: tempfile::TempDir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let outside: tempfile::NamedTempFile =
            tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
        std::fs::write(outside.path(), MARKER).map_err(|error| error.to_string())?;
        let corpus: std::path::PathBuf = root.path().join("corpus");
        std::fs::create_dir(&corpus).map_err(|error| error.to_string())?;
        symlink(outside.path(), corpus.join("approved.py")).map_err(|error| error.to_string())?;
        let error: AuthoredSourceError = match authorize_from_manifest(
            root.path(),
            "corpus/approved.py",
            &manifest(&sha256(MARKER)),
        ) {
            Err(error) => error,
            Ok(path) => {
                return Err(format!(
                    "outside symlink was authorized as {}",
                    path.display()
                ));
            }
        };
        assert!(matches!(
            error,
            AuthoredSourceError::OutsideWorkspace { .. }
        ));
        Ok(())
    }
}
