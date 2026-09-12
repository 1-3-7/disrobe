use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub(crate) const MANIFEST: &str = "corpus/python/pyarmor/MANIFEST.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusManifest {
    pub(crate) meta: Meta,
    pub(crate) payload_header: PayloadHeader,
    pub(crate) license_id_serial: LicenseIdSerial,
    pub(crate) fixture: Vec<Fixture>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Meta {
    pub(crate) pyarmor_v8_version: String,
    pub(crate) pyarmor_v9_version: String,
    pub(crate) pyarmor_cli_core_v8: String,
    pub(crate) pyarmor_cli_core_v9: String,
    pub(crate) license_type: String,
    pub(crate) license_no: String,
    pub(crate) python_target: String,
    pub(crate) build_platform: String,
    pub(crate) total_fixtures: usize,
    pub(crate) v8_fixtures: usize,
    pub(crate) v9_fixtures: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadHeader {
    pub(crate) bytes_0_7_ascii: String,
    pub(crate) byte_8: String,
    pub(crate) byte_9: String,
    pub(crate) byte_10: String,
    pub(crate) byte_11: String,
    pub(crate) bytes_12_15: String,
    #[serde(rename = "bytes_16_19_LE_u32")]
    pub(crate) bytes_16_19_le_u32: String,
    #[serde(rename = "bytes_20_23_LE_u32")]
    pub(crate) bytes_20_23_le_u32: String,
    #[serde(rename = "bytes_24_27_LE_u32")]
    pub(crate) bytes_24_27_le_u32: String,
    #[serde(rename = "bytes_28_31_LE_u32")]
    pub(crate) bytes_28_31_le_u32: String,
    #[serde(rename = "bytes_32_35_LE_u32")]
    pub(crate) bytes_32_35_le_u32: String,
    pub(crate) byte_36: String,
    pub(crate) byte_37: String,
    pub(crate) byte_38: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LicenseIdSerial {
    pub(crate) note: String,
    pub(crate) sample_set: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub(crate) enum CorpusVersion {
    #[serde(rename = "v8")]
    V8,
    #[serde(rename = "v9")]
    V9,
}

impl CorpusVersion {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::V8 => "v8",
            Self::V9 => "v9",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    pub(crate) pyarmor_version: CorpusVersion,
    pub(crate) mode: String,
    pub(crate) chunk: String,
    pub(crate) input_sha256: String,
    pub(crate) output_path: String,
    pub(crate) output_sha256: String,
    pub(crate) output_bytes: u64,
    pub(crate) runtime_path: String,
    pub(crate) runtime_sha256: String,
    pub(crate) runtime_bytes: u64,
    pub(crate) runtime_format: String,
}

#[derive(Debug)]
pub(crate) struct ResolvedFixture {
    pub(crate) pyarmor_version: CorpusVersion,
    pub(crate) wrapper: VerifiedInput,
    pub(crate) runtime: VerifiedInput,
    pub(crate) relative_id: String,
}

#[derive(Debug)]
pub(crate) struct VerifiedInput {
    pub(crate) canonical_path: PathBuf,
    pub(crate) bytes: Box<[u8]>,
}

pub(crate) fn repo_root() -> PathBuf {
    let manifest_dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest_dir.parent().and_then(Path::parent) else {
        panic!(
            "the PyArmor corpus roster lives at {MANIFEST}, two directories above {}, so a manifest path with no grandparent leaves the declared roster checked against nothing",
            manifest_dir.display()
        )
    };
    root.to_path_buf()
}

pub(crate) fn read_manifest() -> CorpusManifest {
    let root: PathBuf = repo_root();
    let path: PathBuf = root.join(MANIFEST);
    let text: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{MANIFEST} is committed evidence behind the published PyArmor figure, so a run that cannot read it must fail rather than report a green that checked nothing: {error} at {}",
            path.display()
        )
    });
    let manifest: CorpusManifest = toml::from_str(&text).unwrap_or_else(|error: toml::de::Error| {
        panic!(
            "{MANIFEST} must deserialize as the typed roster that binds the published population: {error}"
        )
    });
    assert!(
        !manifest.fixture.is_empty(),
        "{MANIFEST} declares zero fixtures, so every corpus test would pass without grading a sample"
    );
    manifest
}

fn resolved_fixtures(
    manifest: &CorpusManifest,
    root: &Path,
    tracked: &BTreeSet<String>,
) -> Vec<ResolvedFixture> {
    let mut fixtures: Vec<ResolvedFixture> = manifest
        .fixture
        .iter()
        .map(|fixture: &Fixture| resolve_fixture(fixture, root, tracked))
        .collect();
    fixtures.sort_by(|left: &ResolvedFixture, right: &ResolvedFixture| {
        left.relative_id.cmp(&right.relative_id)
    });
    fixtures
}

pub(crate) fn verified_fixtures(manifest: &CorpusManifest) -> Vec<ResolvedFixture> {
    let root: PathBuf = repo_root();
    let tracked: BTreeSet<String> = git_tracked_paths(&root);
    assert!(
        tracked.contains(MANIFEST),
        "{MANIFEST} must be tracked before it can define the named PyArmor wrapper population"
    );
    let declared: BTreeSet<String> = declared_output_paths(manifest);
    assert_eq!(
        declared.len(),
        manifest.fixture.len(),
        "{MANIFEST} names one output path more than once, so its declared population aliases a fixture"
    );
    let split_total: usize = manifest
        .meta
        .v8_fixtures
        .checked_add(manifest.meta.v9_fixtures)
        .expect("the v8/v9 fixture split fits usize");
    assert_eq!(
        split_total, manifest.meta.total_fixtures,
        "{MANIFEST} declares a v8/v9 split that does not account for its total fixture population"
    );
    assert_eq!(
        count_version(manifest, CorpusVersion::V8),
        manifest.meta.v8_fixtures,
        "{MANIFEST} labels a different number of fixture blocks as v8 than its pinned v8 count"
    );
    assert_eq!(
        count_version(manifest, CorpusVersion::V9),
        manifest.meta.v9_fixtures,
        "{MANIFEST} labels a different number of fixture blocks as v9 than its pinned v9 count"
    );
    let discovered: BTreeSet<String> = discovered_output_paths();
    assert_eq!(
        declared, discovered,
        "{MANIFEST} and the committed v8/v9 wrapper tree name different populations"
    );
    let fixtures: Vec<ResolvedFixture> = resolved_fixtures(manifest, &root, &tracked);
    assert_eq!(
        fixtures.len(),
        manifest.meta.total_fixtures,
        "{MANIFEST} total_fixtures must equal the validated wrapper/runtime pair count"
    );
    let canonical_wrappers: BTreeSet<PathBuf> = fixtures
        .iter()
        .map(|fixture: &ResolvedFixture| fixture.wrapper.canonical_path.clone())
        .collect();
    assert_eq!(
        canonical_wrappers.len(),
        fixtures.len(),
        "{MANIFEST} names multiple output paths that resolve to the same wrapper file"
    );
    fixtures
}

pub(crate) fn declared_output_paths(manifest: &CorpusManifest) -> BTreeSet<String> {
    manifest
        .fixture
        .iter()
        .map(|fixture: &Fixture| normalized_repo_path(&fixture.output_path))
        .collect()
}

pub(crate) fn discovered_output_paths() -> BTreeSet<String> {
    let root: PathBuf = repo_root();
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for version in [CorpusVersion::V8, CorpusVersion::V9] {
        discover_wrappers(
            &root.join("corpus/python/pyarmor").join(version.label()),
            &mut paths,
        );
    }
    paths
}

pub(crate) fn count_version(manifest: &CorpusManifest, version: CorpusVersion) -> usize {
    manifest
        .fixture
        .iter()
        .filter(|fixture: &&Fixture| fixture.pyarmor_version == version)
        .count()
}

fn resolve_fixture(fixture: &Fixture, root: &Path, tracked: &BTreeSet<String>) -> ResolvedFixture {
    let expected_prefix: String =
        format!("corpus/python/pyarmor/{}/", fixture.pyarmor_version.label());
    assert!(
        fixture.output_path.starts_with(&expected_prefix),
        "{} labels {} as {}, but the output path is outside that version root",
        MANIFEST,
        fixture.output_path,
        fixture.pyarmor_version.label()
    );
    let wrapper_relative: PathBuf = safe_relative_path(&fixture.output_path);
    let runtime_relative: PathBuf = safe_relative_path(&fixture.runtime_path);
    let Some(wrapper_parent): Option<&Path> = wrapper_relative.parent() else {
        panic!(
            "{} has no parent directory, so it cannot pair a wrapper with its runtime",
            fixture.output_path
        )
    };
    assert!(
        runtime_relative.starts_with(wrapper_parent),
        "{} pairs wrapper {} with runtime {}, but the runtime is outside the wrapper directory",
        MANIFEST,
        fixture.output_path,
        fixture.runtime_path
    );
    let wrapper: VerifiedInput = tracked_regular_file(
        root,
        tracked,
        &fixture.output_path,
        fixture.output_bytes,
        &fixture.output_sha256,
    );
    let runtime: VerifiedInput = tracked_regular_file(
        root,
        tracked,
        &fixture.runtime_path,
        fixture.runtime_bytes,
        &fixture.runtime_sha256,
    );
    ResolvedFixture {
        pyarmor_version: fixture.pyarmor_version,
        wrapper,
        runtime,
        relative_id: normalized_repo_path(&fixture.output_path),
    }
}

fn tracked_regular_file(
    root: &Path,
    tracked: &BTreeSet<String>,
    value: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> VerifiedInput {
    let root_canonical: PathBuf = fs::canonicalize(root).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "repository root {} must canonicalize before corpus fixture paths can be bounded: {error}",
            root.display()
        )
    });
    let relative: PathBuf = safe_relative_path(value);
    let normalized: String = relative.to_string_lossy().replace('\\', "/");
    assert!(
        tracked.contains(&normalized),
        "{value} is a named member of {MANIFEST} but git ls-files does not track it"
    );
    let candidate: PathBuf = root.join(&relative);
    let metadata: fs::Metadata = fs::symlink_metadata(&candidate).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{value} is a named member of {MANIFEST}, so an absent entry cannot be treated as an optional fixture: {error} at {}",
            candidate.display()
        )
    });
    assert!(
        metadata.file_type().is_file(),
        "{value} is a named member of {MANIFEST} but is not a regular file"
    );
    let bytes: Vec<u8> = fs::read(&candidate).unwrap_or_else(|error: std::io::Error| {
        panic!("{value} must be readable before its manifest identity is checked: {error}")
    });
    verify_file_identity(value, &bytes, expected_bytes, expected_sha256)
        .unwrap_or_else(|error: String| panic!("{error}"));
    let canonical: PathBuf =
        fs::canonicalize(&candidate).unwrap_or_else(|error: std::io::Error| {
            panic!("{value} must canonicalize for corpus boundary validation: {error}")
        });
    assert!(
        canonical.starts_with(&root_canonical),
        "{value} resolves outside the repository root through an alias"
    );
    VerifiedInput {
        canonical_path: canonical,
        bytes: bytes.into_boxed_slice(),
    }
}

fn git_tracked_paths(root: &Path) -> BTreeSet<String> {
    let output: std::process::Output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--",
            MANIFEST,
            "corpus/python/pyarmor/v8",
            "corpus/python/pyarmor/v9",
        ])
        .current_dir(root)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "git ls-files is required to prove the named PyArmor wrapper population is committed: {error}"
            )
        });
    let stderr: String = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    assert!(
        output.status.success(),
        "git ls-files must enumerate the committed PyArmor wrapper population: {stderr}"
    );
    let raw: String =
        String::from_utf8(output.stdout).unwrap_or_else(|error: std::string::FromUtf8Error| {
            panic!("git ls-files returned a non-UTF-8 PyArmor path: {error}")
        });
    let tracked: BTreeSet<String> = raw
        .split('\0')
        .filter(|entry: &&str| !entry.is_empty())
        .map(|entry: &str| entry.replace('\\', "/"))
        .collect();
    assert!(
        !tracked.is_empty(),
        "git ls-files found no committed PyArmor v8/v9 paths, so the named corpus denominator is absent"
    );
    tracked
}

pub(crate) fn verify_file_identity(
    value: &str,
    bytes: &[u8],
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    let actual_bytes: u64 =
        u64::try_from(bytes.len()).map_err(|error: core::num::TryFromIntError| {
            format!("byte length does not fit u64: {error}")
        })?;
    if actual_bytes != expected_bytes {
        return Err(format!(
            "{value} has {actual_bytes} bytes in this checkout, but {MANIFEST} records {expected_bytes}"
        ));
    }
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte: u8| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "{value}: {MANIFEST} records a SHA-256 that is not exactly 64 hexadecimal characters"
        ));
    }
    let actual_sha256: String = sha256_hex(bytes);
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "{value} has SHA-256 {actual_sha256}, but {MANIFEST} records {expected_sha256}"
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn normalized_repo_path(value: &str) -> String {
    let relative: PathBuf = safe_relative_path(value);
    relative.to_string_lossy().replace('\\', "/")
}

fn safe_relative_path(value: &str) -> PathBuf {
    assert!(
        !value.contains('\\'),
        "{value} uses an alternate path separator, so it cannot be a canonical repository-relative manifest path"
    );
    let path: &Path = Path::new(value);
    assert!(
        !path.is_absolute(),
        "{value} is absolute, so it cannot name a tracked corpus fixture"
    );
    let mut normalized: PathBuf = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                panic!("{value} is not a normalized repository-relative manifest path")
            }
        }
    }
    assert!(
        !normalized.as_os_str().is_empty(),
        "a manifest fixture path cannot be empty"
    );
    normalized
}

fn discover_wrappers(dir: &Path, paths: &mut BTreeSet<String>) {
    let entries: fs::ReadDir = fs::read_dir(dir).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is one of the committed v8/v9 corpus roots, so it must be readable when deriving the published denominator: {error}",
            dir.display()
        )
    });
    let mut children: Vec<PathBuf> = entries
        .map(|entry: Result<fs::DirEntry, std::io::Error>| {
            entry
                .unwrap_or_else(|error: std::io::Error| {
                    panic!("{} has an unreadable corpus entry: {error}", dir.display())
                })
                .path()
        })
        .collect();
    children.sort();
    for path in children {
        let metadata: fs::Metadata =
            fs::symlink_metadata(&path).unwrap_or_else(|error: std::io::Error| {
                panic!(
                    "{} must be inspectable while deriving the corpus population: {error}",
                    path.display()
                )
            });
        if metadata.file_type().is_dir() {
            discover_wrappers(&path, paths);
            continue;
        }
        if !is_chunk_wrapper(&path) {
            continue;
        }
        assert!(
            metadata.file_type().is_file(),
            "{} looks like a counted wrapper but is not a regular file",
            path.display()
        );
        let root: PathBuf = repo_root();
        let canonical_root: PathBuf =
            fs::canonicalize(&root).unwrap_or_else(|error: std::io::Error| {
                panic!(
                    "{} must canonicalize before candidate paths can be bounded: {error}",
                    root.display()
                )
            });
        let canonical: PathBuf = fs::canonicalize(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{} must canonicalize while deriving the corpus population: {error}",
                path.display()
            )
        });
        let relative: &Path = canonical.strip_prefix(&canonical_root).unwrap_or_else(|_| {
            panic!(
                "{} resolves outside the repository root through an alias",
                path.display()
            )
        });
        let normalized: String = relative.to_string_lossy().replace('\\', "/");
        assert!(
            paths.insert(normalized.clone()),
            "{normalized} aliases another discovered wrapper, so the denominator would count one file twice"
        );
    }
}

fn is_chunk_wrapper(path: &Path) -> bool {
    let Some(name): Option<&str> = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    name.starts_with("chunk")
        && path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension: &str| extension.eq_ignore_ascii_case("py"))
}
