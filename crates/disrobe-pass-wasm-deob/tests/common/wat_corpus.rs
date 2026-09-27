#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use disrobe_pass_wasm_deob::{CalleeNames, ModuleSignatures};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasmparser::{FunctionBody, Parser, Payload};

const PROVENANCE_PATH: &str = "tests/golden/authored_wat_provenance.toml";
const PROVENANCE_SCHEMA: &str = "disrobe.authored-wat-provenance/v1";

#[derive(Debug, Deserialize)]
struct Provenance {
    schema: String,
    execution_fixture_claim: String,
    execution_fixture_limit: String,
    root: Vec<ProvenanceRoot>,
    artifact: Vec<ProvenanceArtifact>,
    execution_fixture: Vec<ProvenanceArtifact>,
}

#[derive(Debug, Deserialize)]
struct ProvenanceRoot {
    path: String,
    claim: String,
    limit: String,
}

#[derive(Debug, Deserialize)]
struct ProvenanceArtifact {
    path: String,
    sha256: String,
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("resolve workspace root from CARGO_MANIFEST_DIR: {error}")
        })
}

pub fn corpus_dirs() -> Vec<PathBuf> {
    let root: PathBuf = workspace_root();
    vec![
        root.join("corpus").join("src").join("wasm").join("sources"),
        root.join("corpus")
            .join("src")
            .join("wasm")
            .join("edge_cases"),
        root.join("corpus").join("wasm").join("wat"),
        root.join("corpus").join("wasm").join("plugins"),
    ]
}

fn provenance() -> &'static Provenance {
    static PROVENANCE: OnceLock<Provenance> = OnceLock::new();
    PROVENANCE.get_or_init(|| {
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_PATH);
        let text: String = fs::read_to_string(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let parsed: Provenance = toml::from_str(&text)
            .unwrap_or_else(|error: toml::de::Error| panic!("parse {}: {error}", path.display()));
        assert_eq!(
            parsed.schema,
            PROVENANCE_SCHEMA,
            "{} declares an unknown schema",
            path.display()
        );
        parsed
    })
}

fn checked_relative(path: &str) -> PathBuf {
    let parsed: PathBuf = PathBuf::from(path);
    assert!(
        !parsed.is_absolute()
            && parsed
                .components()
                .all(|component: Component<'_>| { matches!(component, Component::Normal(_)) }),
        "WAT provenance path must be a relative normal path: {path}"
    );
    parsed
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn assert_sha256(path: &str, expected: &str, bytes: &[u8]) {
    assert_eq!(
        sha256_hex(bytes),
        expected,
        "{path} changed since its authored WAT provenance was pinned"
    );
}

fn provenance_artifacts() -> BTreeMap<String, String> {
    let provenance: &Provenance = provenance();
    let roots: BTreeSet<String> = provenance
        .root
        .iter()
        .map(|root: &ProvenanceRoot| {
            assert!(
                !root.claim.trim().is_empty() && !root.limit.trim().is_empty(),
                "{} has an incomplete authored-source claim",
                root.path
            );
            checked_relative(&root.path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    let expected_roots: BTreeSet<String> = corpus_dirs()
        .iter()
        .map(|path: &PathBuf| corpus_key(path))
        .collect();
    assert_eq!(
        roots, expected_roots,
        "authored WAT provenance roots differ from the runtime corpus roots"
    );
    let artifacts: BTreeMap<String, String> = provenance
        .artifact
        .iter()
        .map(|artifact: &ProvenanceArtifact| {
            let key: String = checked_relative(&artifact.path)
                .to_string_lossy()
                .replace('\\', "/");
            assert!(
                roots
                    .iter()
                    .any(|root: &String| key.starts_with(&format!("{root}/"))),
                "{key} is outside an authored WAT provenance root"
            );
            assert!(
                artifact.sha256.len() == 64
                    && artifact
                        .sha256
                        .bytes()
                        .all(|byte: u8| byte.is_ascii_hexdigit()),
                "{key} has an invalid SHA-256 provenance digest"
            );
            (key, artifact.sha256.clone())
        })
        .collect();
    assert_eq!(
        artifacts.len(),
        provenance.artifact.len(),
        "authored WAT provenance lists an artifact more than once"
    );
    artifacts
}

fn execution_fixture_artifacts() -> BTreeMap<String, String> {
    assert!(
        !provenance().execution_fixture_claim.trim().is_empty()
            && !provenance().execution_fixture_limit.trim().is_empty(),
        "authored execution fixtures have an incomplete provenance claim"
    );
    let artifacts: BTreeMap<String, String> = provenance()
        .execution_fixture
        .iter()
        .map(|artifact: &ProvenanceArtifact| {
            let key: String = checked_relative(&artifact.path)
                .to_string_lossy()
                .replace('\\', "/");
            assert!(
                key.starts_with("crates/disrobe-pass-wasm-deob/tests/fixtures/")
                    && Path::new(&key).extension() == Some(OsStr::new("wat")),
                "{key} is outside the authored execution-fixture set"
            );
            assert!(
                artifact.sha256.len() == 64
                    && artifact
                        .sha256
                        .bytes()
                        .all(|byte: u8| byte.is_ascii_hexdigit()),
                "{key} has an invalid SHA-256 provenance digest"
            );
            (key, artifact.sha256.clone())
        })
        .collect();
    assert_eq!(
        artifacts.len(),
        provenance().execution_fixture.len(),
        "authored execution-fixture provenance lists a fixture more than once"
    );
    assert_eq!(
        artifacts.len(),
        17,
        "the Wasmtime execution-fixture provenance roster changed"
    );
    artifacts
}

pub fn verify_execution_fixture(name: &str, embedded: &str) {
    let artifacts: BTreeMap<String, String> = execution_fixture_artifacts();
    let root: PathBuf = workspace_root();
    for (key, expected) in &artifacts {
        let path: PathBuf =
            root.join(key)
                .canonicalize()
                .unwrap_or_else(|error: std::io::Error| {
                    panic!("resolve authored execution fixture {key}: {error}")
                });
        assert!(
            path.starts_with(&root),
            "authored execution fixture escapes workspace: {}",
            path.display()
        );
        let bytes: Vec<u8> = fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        assert_sha256(key, expected, &bytes);
    }
    let key: String = format!("crates/disrobe-pass-wasm-deob/tests/fixtures/{name}");
    let expected: &String = artifacts
        .get(&key)
        .unwrap_or_else(|| panic!("{key} is not an authored Wasmtime execution fixture"));
    assert_sha256(&key, expected, embedded.as_bytes());
}

pub fn verified_wat_files() -> Vec<PathBuf> {
    let artifacts: BTreeMap<String, String> = provenance_artifacts();
    let root: PathBuf = workspace_root();
    let mut discovered: BTreeMap<String, PathBuf> = BTreeMap::new();
    for directory in corpus_dirs() {
        let entries: fs::ReadDir =
            fs::read_dir(&directory).unwrap_or_else(|error: std::io::Error| {
                panic!(
                    "read authored WAT directory {}: {error}",
                    directory.display()
                )
            });
        for entry in entries {
            let path: PathBuf = entry
                .unwrap_or_else(|error: std::io::Error| panic!("read authored WAT entry: {error}"))
                .path();
            if path
                .extension()
                .is_some_and(|extension: &std::ffi::OsStr| extension == "wat")
            {
                let metadata: fs::Metadata =
                    fs::symlink_metadata(&path).unwrap_or_else(|error: std::io::Error| {
                        panic!("stat {}: {error}", path.display())
                    });
                assert!(
                    !metadata.file_type().is_symlink(),
                    "authored WAT input must not be a symlink: {}",
                    path.display()
                );
                let normalized: PathBuf =
                    path.canonicalize().unwrap_or_else(|error: std::io::Error| {
                        panic!("resolve authored WAT path {}: {error}", path.display())
                    });
                let key: String = normalized
                    .strip_prefix(&root)
                    .unwrap_or_else(|_| {
                        panic!(
                            "authored WAT path escapes workspace: {}",
                            normalized.display()
                        )
                    })
                    .to_string_lossy()
                    .replace('\\', "/");
                discovered.insert(key, normalized);
            }
        }
    }
    let discovered_keys: BTreeSet<String> = discovered.keys().cloned().collect();
    let artifact_keys: BTreeSet<String> = artifacts.keys().cloned().collect();
    assert_eq!(
        discovered_keys, artifact_keys,
        "authored WAT provenance roster differs from the runtime corpus"
    );
    for (key, path) in &discovered {
        let bytes: Vec<u8> = fs::read(path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let expected: &String = artifacts
            .get(key)
            .unwrap_or_else(|| panic!("missing provenance for {key}"));
        assert_sha256(key, expected, &bytes);
    }
    discovered.into_values().collect()
}

pub fn verified_wat_text(path: &Path) -> String {
    let root: PathBuf = workspace_root();
    let normalized: PathBuf = path
        .canonicalize()
        .unwrap_or_else(|error: std::io::Error| panic!("resolve {}: {error}", path.display()));
    let key: String = normalized
        .strip_prefix(&root)
        .unwrap_or_else(|_| {
            panic!(
                "authored WAT path escapes workspace: {}",
                normalized.display()
            )
        })
        .to_string_lossy()
        .replace('\\', "/");
    let files: Vec<PathBuf> = verified_wat_files();
    assert!(
        files
            .iter()
            .any(|candidate: &PathBuf| candidate == &normalized),
        "{key} is not an authored WAT runtime input"
    );
    let text: String = fs::read_to_string(&normalized)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", normalized.display()));
    let artifacts: BTreeMap<String, String> = provenance_artifacts();
    let expected: &String = artifacts
        .get(&key)
        .unwrap_or_else(|| panic!("missing provenance for {key}"));
    assert_sha256(&key, expected, text.as_bytes());
    text
}

pub fn corpus_key(path: &Path) -> String {
    let root: PathBuf = workspace_root();
    let relative: &Path = path.strip_prefix(&root).unwrap_or(path);
    relative
        .components()
        .filter_map(|component: Component<'_>| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<String>>()
        .join("/")
}

#[test]
#[should_panic(expected = "changed since its authored WAT provenance was pinned")]
fn altered_authored_wat_bytes_are_rejected() {
    assert_sha256(
        "corpus/wasm/plugins/compute_xor.wat",
        "069d2b2ffdb50f24ea6aa2fca61eb0973655538a95ef79bfb66bd374365d155c",
        b"(module (func))",
    );
}

#[test]
#[should_panic(expected = "changed since its authored WAT provenance was pinned")]
fn altered_execution_fixture_bytes_are_rejected() {
    verify_execution_fixture("simd_diff.wat", "(module (func))");
}

pub fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

pub fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}
